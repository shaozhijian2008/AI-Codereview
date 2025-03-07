import atexit
import json
import os
import traceback
from datetime import datetime
from multiprocessing import Process

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from flask import Flask, request, jsonify

from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity
from biz.event.event_manager import event_manager
from biz.gitlab.webhook_handler import MergeRequestHandler, PushHandler
from biz.gitea.webhook_handler import handle_event
from biz.service.review_service import ReviewService
from biz.utils.code_reviewer import CodeReviewer
from biz.utils.im import im_notifier
from biz.utils.log import logger
from biz.utils.reporter import Reporter

load_dotenv()
api_app = Flask(__name__)


@api_app.route("/")
def home():
    return """<h2>The code review api server is running.</h2>
              <p>GitHub project address: <a href="https://github.com/sunmh207/AI-Codereview-Gitlab" target="_blank">
              https://github.com/sunmh207/AI-Codereview-Gitlab</a></p>
              <p>Gitee project address: <a href="https://gitee.com/sunminghui/ai-codereview-gitlab" target="_blank">https://gitee.com/sunminghui/ai-codereview-gitlab</a></p>
              """


@api_app.route("/review/daily_report", methods=["GET"])
def daily_report():
    # 获取当前日期0点和23点59分59秒的时间戳
    start_time = (
        datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    )
    end_time = (
        datetime.now().replace(hour=23, minute=59, second=59, microsecond=0).timestamp()
    )

    try:
        df = ReviewService().get_mr_review_logs(
            updated_at_gte=start_time, updated_at_lte=end_time
        )

        if df.empty:
            logger.info("No data to process.")
            return jsonify({"message": "No data to process."}), 200
        # 去重：基于 (author, message) 组合
        df_unique = df.drop_duplicates(subset=["author", "commit_messages"])
        # 按照 author 排序
        df_sorted = df_unique.sort_values(by="author")
        # 转换为适合生成日报的格式
        commits = df_sorted.to_dict(orient="records")
        # 生成日报内容
        report_txt = Reporter().generate_report(json.dumps(commits))
        # 发送钉钉通知
        im_notifier.send_notification(
            content=report_txt, msg_type="markdown", title="代码提交日报"
        )

        # 返回生成的日报内容
        return json.dumps(report_txt, ensure_ascii=False, indent=4)
    except Exception as e:
        logger.error(f"Failed to generate daily report: {e}")
        return jsonify({"message": f"Failed to generate daily report: {e}"}), 500


# 启动定时生成日报的任务
scheduler = BackgroundScheduler()
crontab_expression = os.getenv("REPORT_CRONTAB_EXPRESSION", "0 22 * * 1-5")
cron_parts = crontab_expression.split()
cron_minute, cron_hour, cron_day, cron_month, cron_day_of_week = cron_parts

# Schedule the task based on the crontab expression
scheduler.add_job(
    daily_report,
    trigger=CronTrigger(
        minute=cron_minute,
        hour=cron_hour,
        day=cron_day,
        month=cron_month,
        day_of_week=cron_day_of_week,
    ),
)

# Start the scheduler
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())


# 处理 GitLab Merge Request Webhook
@api_app.route("/review/webhook", methods=["POST"])
def handle_webhook():
    # 获取请求的JSON数据
    if request.is_json:
        if handle_event(request):
            return (
                jsonify({"message": "Request received, will process asynchronously."}),
                200,
            )

        data = request.get_json()
        event_type = request.headers.get("X-Gitlab-Event")
        # 优先从请求头获取，如果没有，则从环境变量获取
        gitlab_url = request.headers.get("X-Gitlab-Instance") or os.getenv("GITLAB_URL")
        gitlab_token = request.headers.get("X-Gitlab-Token")
        # 优先从环境变量获取，如果没有，则从请求头获取
        gitlab_token = os.getenv("GITLAB_ACCESS_TOKEN") or request.headers.get(
            "X-Gitlab-Token"
        )
        # 如果gitlab_token为空，返回错误
        if not gitlab_token:
            return jsonify({"message": "Missing GitLab access token"}), 400

        # 打印整个payload数据，或根据需求进行处理
        logger.info(f"Received event: {event_type}")
        logger.info(f"Payload: {json.dumps(data)}")

        # 处理Merge Request Hook
        if event_type == "Merge Request Hook":
            # 创建一个新进程进行异步处理
            process = Process(
                target=__handle_merge_request_event,
                args=(data, gitlab_token, gitlab_url),
            )
            process.start()
            # 立马返回响应
            return (
                jsonify({"message": "Request received, will process asynchronously."}),
                200,
            )
        elif event_type == "Push Hook":
            # 创建一个新进程进行异步处理
            process = Process(
                target=__handle_push_event, args=(data, gitlab_token, gitlab_url)
            )
            process.start()
            # 立马返回响应
            return (
                jsonify({"message": "Request received, will process asynchronously."}),
                200,
            )
        else:
            return jsonify({"message": "Event type not supported"}), 400
    else:
        return jsonify({"message": "Invalid data format"}), 400


def __handle_push_event(webhook_data: dict, gitlab_token: str, gitlab_url: str):
    try:
        handler = PushHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info("Push Hook event received")
        commits = handler.get_push_commits()
        if not commits:
            logger.error("Failed to get commits")
            return

            # review 代码
        PUSH_REVIEW_ENABLED = os.environ.get("PUSH_REVIEW_ENABLED", "0") == "1"
        review_result = None
        score = 0
        if PUSH_REVIEW_ENABLED:
            # 获取PUSH的changes
            changes = handler.get_push_changes()
            logger.info("changes: %s", changes)
            changes = filter_changes(changes)
            if not changes:
                logger.info(
                    "未检测到PUSH代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。"
                )
            review_result = "关注的文件没有修改"

            if len(changes) > 0:
                commits_text = ";".join(
                    commit.get("message", "").strip() for commit in commits
                )
                review_result = review_code(str(changes), commits_text)
                score = CodeReviewer.parse_review_score(review_text=review_result)
            # 将review结果提交到Gitlab的 notes
            handler.add_push_notes(f"Auto Review Result: \n{review_result}")

        event_manager["push_reviewed"].send(
            PushReviewEntity(
                project_name=webhook_data["project"]["name"],
                author=webhook_data["user_username"],
                branch=webhook_data["project"]["default_branch"],
                updated_at=int(datetime.now().timestamp()),  # 当前时间
                commits=commits,
                score=score,
                review_result=review_result,
            )
        )

    except Exception as e:
        error_message = f"服务出现未知错误: {str(e)}\n{traceback.format_exc()}"
        im_notifier.send_notification(content=error_message)
        logger.error("出现未知错误: %s", error_message)


def __handle_merge_request_event(
    webhook_data: dict, gitlab_token: str, gitlab_url: str
):
    """
    处理Merge Request Hook事件
    :param webhook_data:
    :param gitlab_token:
    :param gitlab_url:
    :return:
    """
    try:
        # 解析Webhook数据
        handler = MergeRequestHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info("Merge Request Hook event received")

        if handler.action in ["open", "update"]:  # 仅仅在MR创建或更新时进行Code Review
            # 获取Merge Request的changes
            changes = handler.get_merge_request_changes()
            logger.info("changes: %s", changes)
            changes = filter_changes(changes)
            if not changes:
                logger.info(
                    "未检测到有关代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。"
                )
                return

            # 获取Merge Request的commits
            commits = handler.get_merge_request_commits()
            if not commits:
                logger.error("Failed to get commits")
                return

            # review 代码
            commits_text = ";".join(commit["title"] for commit in commits)
            review_result = review_code(str(changes), commits_text)

            # 将review结果提交到Gitlab的 notes
            handler.add_merge_request_notes(f"Auto Review Result: \n{review_result}")

            # dispatch merge_request_reviewed event
            event_manager["merge_request_reviewed"].send(
                MergeRequestReviewEntity(
                    project_name=webhook_data["project"]["name"],
                    author=webhook_data["user"]["username"],
                    source_branch=webhook_data["object_attributes"]["source_branch"],
                    target_branch=webhook_data["object_attributes"]["target_branch"],
                    updated_at=int(datetime.now().timestamp()),
                    commits=commits,
                    score=CodeReviewer.parse_review_score(review_text=review_result),
                    url=webhook_data["object_attributes"]["url"],
                    review_result=review_result,
                )
            )

        else:
            logger.info(f"Merge Request Hook event, action={handler.action}, ignored.")

    except Exception as e:
        error_message = (
            f"AI Code Review 服务出现未知错误: {str(e)}\n{traceback.format_exc()}"
        )
        im_notifier.send_notification(content=error_message)
        logger.error("出现未知错误: %s", error_message)


def filter_changes(changes: list):
    """
    过滤数据，只保留支持的文件类型以及必要的字段信息
    """
    filter_deleted_files_changes = [
        change for change in changes if change.get("deleted_file") == False
    ]
    # 从环境变量中获取支持的文件扩展名
    SUPPORTED_EXTENSIONS = os.getenv("SUPPORTED_EXTENSIONS", ".java,.py,.php").split(
        ","
    )
    # 过滤 `new_path` 以支持的扩展名结尾的元素, 仅保留diff和new_path字段
    filtered_changes = [
        {"diff": item["diff"], "new_path": item["new_path"]}
        for item in filter_deleted_files_changes
        if any(item.get("new_path", "").endswith(ext) for ext in SUPPORTED_EXTENSIONS)
    ]
    return filtered_changes


def review_code(changes_text: str, commits_text: str = "") -> str:
    # 如果超长，取前REVIEW_MAX_LENGTH字符
    review_max_length = int(os.getenv("REVIEW_MAX_LENGTH", 5000))
    # 如果changes为空,打印日志
    if not changes_text:
        logger.info("代码为空, diffs_text = %", str(changes_text))
        return "代码为空"

    if len(changes_text) > review_max_length:
        changes_text = changes_text[:review_max_length]
        logger.info(f"文本超长，截段后content: {changes_text}")
    review_result = CodeReviewer().review_code(changes_text, commits_text).strip()
    if review_result.startswith("```markdown") and review_result.endswith("```"):
        return review_result[11:-3].strip()
    return review_result


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 5001))
    api_app.run(host="0.0.0.0", port=port)
