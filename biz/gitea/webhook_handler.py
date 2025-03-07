from datetime import datetime
import json
from multiprocessing import Process
import os
import time
import re

import requests
from flask import Flask, Request, jsonify

from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity
from biz.event.event_manager import event_manager
from biz.utils.log import logger
from biz.utils.code_reviewer import CodeReviewer


class GiteaPullRequestHandler:
    def __init__(self, webhook_data: dict, gitea_token: str, gitea_url: str):
        self.webhook_data = webhook_data
        self.token = gitea_token
        self.url = gitea_url
        self.owner = None
        self.repo = None
        # self.commits = None
        self.number = None
        self.parse_pull_request_event()

    def parse_pull_request_event(self):
        # 提取 Pull Request 的相关参数
        # self.action = self.webhook_data.get('action')
        self.number = self.webhook_data.get("number")
        # self.commits = self.webhook_data.get('repository').get('body')

        full_name = self.webhook_data.get("repository").get("full_name").split("/")
        self.owner = full_name[0]
        self.repo = full_name[1]

    def get_pull_request_changes(self) -> list:
        # 检查是否为 Pull Request Hook 事件
        # if self.event_type != 'pull_request':
        #     logger.warning(f"Invalid event type: {self.event_type}. Only 'pull_request' event is supported now.")
        #     return []

        # Gitea pull request changes API可能存在延迟，多次尝试
        max_retries = 3  # 最大重试次数
        retry_delay = 10  # 重试间隔时间（秒）
        for attempt in range(max_retries):
            # 调用 Gitea API 获取 Pull Request 的 changes
            url = f"{self.url}/api/v1/repos/{self.owner}/{self.repo}/pulls/{self.number}.diff?access_token={self.token}"
            # headers = {
            #     'Authorization': f'token {self.gitea_token}'
            # }
            res = requests.get(url, verify=False)

            # 检查请求是否成功
            if res.status_code == 200 and res.text != "":
                diff_blocks = re.split("diff --git ", res.text.strip())
                # 去掉空字符串
                diff_blocks = [block for block in diff_blocks if block]
                # 移除 'diff --git ' 前缀
                diff_blocks = [
                    block.replace("diff --git ", "") for block in diff_blocks
                ]
                return diff_blocks
            else:
                logger.error(
                    f"Get changes response from Gitea (attempt {attempt + 1}): {res.status_code}, {res.text}, URL: {url}"
                )
                time.sleep(retry_delay)

        logger.warning(f"Max retries ({max_retries}) reached. Changes is still empty.")
        return []  # 达到最大重试次数后返回空列表

    def create_comment(self, file_name: str, diff_content: str, response: str) -> str:
        return f"文件名：{file_name} \n\r 文件变更:\n\r ``` \n\r{diff_content} \n\r ``` \n\r ## 审查结果：\n\r {response}"

    def get_commits(self) -> list:
        # 检查是否为 Push 事件
        # if self.event_type != "pull_request":
        #     logger.warning(
        #         f"Invalid event type: {self.event_type}. Only 'push' event is supported now."
        #     )
        #     return []

        # 提取提交信息
        commit_details = []
        # for commit in self.webhook_data.get("commits", []):
        commit_info = {
            "message": self.webhook_data.get("pull_request").get("body"),
            "author": self.webhook_data.get("pull_request")
            .get("user", {})
            .get("login"),
            "timestamp": self.webhook_data.get("pull_request").get("created_at"),
            "url": self.webhook_data.get("pull_request").get("url"),
        }
        commit_details.append(commit_info)

        logger.info(f"Collected {len(commit_details)} commits from push event.")
        return commit_details

    def add_pull_request_comments(self, comments):
        url = f"{self.url}/api/v1/repos/{self.owner}/{self.repo}/pulls/{self.number}/reviews?token={self.token}"
        headers = {
            # 'Authorization': f'token {self.gitea_token}',
            "Content-Type": "application/json"
        }
        data = {"body": comments}
        response = requests.post(url, headers=headers, json=data, verify=False)
        # logger.debug(f"Add comments to Gitea {url}: {response.status_code}, {response.text}")
        if response.status_code == 201:
            logger.info("comments successfully added to pull request.")
        else:
            logger.error(f"Failed to add comment: {response.status_code}")
            logger.error(response.text)

    def handle_event(self):
        changes = self.get_pull_request_changes()
        if not changes:
            logger.warning("No changes found in the pull request.")
            return

        review_results = []
        supported_file_suffix = os.getenv(
            "SUPPORTED_EXTENSIONS", ".go,.java,.py,.php,.js,.ts"
        ).split(",")

        for diff_content in changes:
            # 提取文件路径
            file_path_match = re.search(r"a/(.*?) b/(.*?)\n", diff_content)
            if file_path_match:
                file_name = file_path_match.group(1)  # 或者 group(2)，两者通常相同
            else:
                logger.warning(f"Failed to extract file path from diff block: ")
                # continue
                file_path = diff_content.split(" ")[0].split("/")
                file_name = file_path[-1]
            if not any(file_name.endswith(suffix) for suffix in supported_file_suffix):
                logger.warning(f"File {file_name} is ignored")
                continue

            review_result = review_code(
                diff_content, self.webhook_data.get("repository").get("body")
            )
            review_results.append(
                create_report_comment(file_name, diff_content, review_result)
            )
            comments = self.create_comment(file_name, "", review_result)
            self.add_pull_request_comments(comments)

        # 记录审查结果
        if review_results:
            event_manager["merge_request_reviewed"].send(
                MergeRequestReviewEntity(
                    project_name=self.repo,
                    author=self.webhook_data.get("pull_request", {})
                    .get("user", {})
                    .get("login"),
                    source_branch=self.webhook_data.get("pull_request", {})
                    .get("head", {})
                    .get("ref"),
                    target_branch=self.webhook_data.get("pull_request", {})
                    .get("base", {})
                    .get("ref"),
                    updated_at=int(datetime.now().timestamp()),  # 当前时间
                    commits=self.get_commits(),
                    score=CodeReviewer.parse_review_score(
                        review_text="\n\n".join(review_results)
                    ),
                    url=self.webhook_data.get("pull_request", {}).get("url"),
                    review_result="\n\n".join(review_results),
                )
            )


class GiteaPushHandler:
    def __init__(self, webhook_data: dict, gitea_token: str, gitea_url: str):
        self.webhook_data = webhook_data
        self.token = gitea_token
        self.host = gitea_url
        # self.event_type = None
        self.repository = None
        self.branch_name = None
        self.commit_list = []
        self.parse_push_event()

    def parse_push_event(self):
        # 提取 Push 事件的相关参数
        self.repository = self.webhook_data.get("repository", {}).get("id")
        self.branch_name = self.webhook_data.get("ref", "").replace("refs/heads/", "")
        self.commit_list = self.webhook_data.get("commits", [])

    def get_push_commits(self) -> list:
        # 检查是否为 Push 事件
        # if self.event_type != "push":
        #     logger.warning(
        #         f"Invalid event type: {self.event_type}. Only 'push' event is supported now."
        #     )
        #     return []

        # 提取提交信息
        commit_details = []
        for commit in self.webhook_data.get("commits", []):
            commit_info = {
                "message": commit.get("message"),
                "author": commit.get("author", {}).get("name"),
                "timestamp": commit.get("timestamp"),
                "url": commit.get("url"),
            }
            commit_details.append(commit_info)

        logger.info(f"Collected {len(commit_details)} commits from push event.")
        return commit_details

    def get_diff_blocks(self, owner: str, repo: str, sha: str) -> str:
        # Get the diff of the commit
        endpoint = f"{self.host}/api/v1/repos/{owner}/{repo}/git/commits/{sha}.diff?access_token={self.token}"
        res = requests.get(endpoint, verify=False)
        if res.status_code == 200 and res.text != "":
            diff_blocks = re.split("diff --git ", res.text.strip())
            # 去掉空字符串
            diff_blocks = [block for block in diff_blocks if block]
            # 移除 'diff --git ' 前缀
            diff_blocks = [block.replace("diff --git ", "") for block in diff_blocks]
            return diff_blocks
        else:
            logger.error(f"Failed to get diff content: {res.text}")
            return None

    def create_issue(
        self, owner: str, repo: str, title: str, body: str, ref: str, pusher: str
    ):
        endpoint = (
            f"{self.host}/api/v1/repos/{owner}/{repo}/issues?access_token={self.token}"
        )
        data = {
            # "assignee": "jenkins",
            #  assignee 填谁
            "assignee": f"{pusher}",
            "assignees": [pusher],
            "body": body,
            "closed": False,
            "due_date": None,
            "labels": [0],
            "milestone": 0,
            "ref": ref,
            "title": title,
        }
        res = requests.post(endpoint, json=data, verify=False)
        if res.status_code == 201:
            return res.json()
        else:
            logger.error(f"Failed to create issue: {res.text}")
            return None

    def add_issue_comment(self, owner, repo, issue_id, comment):
        endpoint = f"{self.host}/api/v1/repos/{owner}/{repo}/issues/{issue_id}/comments?access_token={self.token}"
        data = {
            "body": comment,
        }
        res = requests.post(endpoint, json=data, verify=False)
        if res.status_code == 201:
            return res.json()
        else:
            return None

    def handle_event(self):
        owner, repo, sha, ref, pusher, full_name, title, commit_url = (
            extract_info_from_request(self.webhook_data)
        )

        if "[skip codereview]" in title:
            return {"message": "Skip codereview"}

        diff_blocks = self.get_diff_blocks(owner, repo, sha)
        if diff_blocks is None:
            return {"message": "Failed to get diff content"}

        review_results = []
        current_issue_id = None

        # ignored_file_suffix = config.ignored_file_suffix.split(",")
        # 从环境变量中获取支持的文件扩展名
        supported_file_suffix = os.getenv(
            "SUPPORTED_EXTENSIONS", ".go,.java,.py,.php,.js,.ts"
        ).split(",")

        for i, diff_content in enumerate(diff_blocks, start=1):
            # file_path = diff_content.split(" ")[0].split("/")
            # file_name = file_path[-1]

            # 提取文件路径
            file_path_match = re.search(r"a/(.*?) b/(.*?)\n", diff_content)
            if file_path_match:
                file_name = file_path_match.group(1)  # 或者 group(2)，两者通常相同
            else:
                logger.warning(f"Failed to extract file path from diff block: ")
                # continue
                file_path = diff_content.split(" ")[0].split("/")
                file_name = file_path[-1]

            # Ignore the file if it's in the ignored list
            if not any(file_name.endswith(suffix) for suffix in supported_file_suffix):
                logger.warning(f"File {file_name} is ignored")
                continue

            # Send the diff to ChatGPT for code analysis)
            review_result = review_code(diff_content)

            comment = create_comment(file_name, diff_content, review_result)
            review_results.append(
                create_report_comment(file_name, diff_content, review_result)
            )
            if i == 1:
                issue_res = self.create_issue(
                    owner,
                    repo,
                    f"Code Review {title}",
                    f"本次提交：{commit_url} \n\r 提交人：{pusher} \n\r {comment}",
                    ref,
                    pusher,
                )
                issue_url = issue_res["html_url"]
                current_issue_id = issue_res["number"]

                logger.info(f"The code review: {issue_url}")

                # Send a notification to the webhook
                # if config.webhook.is_init:
                #     headers = {}
                #     if config.webhook.header_name and config.webhook.header_value:
                #         headers = {
                #             config.webhook.header_name: config.webhook.header_value
                #         }

                #     content = (
                #         f"Code Review: {title}\n{commit_url}\n\n审查结果: \n{issue_url}"
                #     )
                #     request_body_str = config.webhook.request_body.format(
                #         content=content,
                #         mention=full_name,
                #     )
                #     request_body = json.loads(request_body_str, strict=False)
                #     requests.post(
                #         config.webhook.url,
                #         headers=headers,
                #         json=request_body,
                #     )

            else:
                self.add_issue_comment(
                    owner,
                    repo,
                    current_issue_id,
                    comment,
                )

            # logger.info("Sleep for 1.5 seconds...")
            # time.sleep(1.5)

        # add banner to the issue
        # self.add_issue_comment(
        #     owner,
        #     repo,
        #     current_issue_id,
        #     # self.banner,
        # )

        event_manager["push_reviewed"].send(
            PushReviewEntity(
                project_name=repo,
                author=owner,
                branch=self.webhook_data.get("ref", "").replace("refs/heads/", ""),
                updated_at=int(datetime.now().timestamp()),  # 当前时间
                commits=self.get_push_commits(),
                score=CodeReviewer.parse_review_score(review_text=review_result),
                review_result="\n\n".join(review_results),
            )
        )

        return {"message": review_result}


def handle_event(request: Request):
    event_type = request.headers.get("X-Gitea-Event")
    if not event_type:
        return False

    data = request.get_json()

    # 打印整个payload数据，或根据需求进行处理
    logger.info(f"Received event: {event_type}")
    logger.info(f"Payload: {json.dumps(data)}")

    token = os.getenv("GITEA_TOKEN")
    url = os.getenv("GITEA_URL")
    if event_type == "push":
        handle = GiteaPushHandler(data, token, url)
        process = Process(target=handle.handle_event)
        process.start()
    if event_type == "pull_request":
        handle = GiteaPullRequestHandler(data, token, url)
        process = Process(target=handle.handle_event)
        process.start()
    else:
        logger.warning(f"Unsupported event type: {event_type}")

    # 立马返回响应
    return jsonify({"message": "Request received, will process asynchronously."}), 200


def extract_info_from_request(request_body):
    full_name = request_body["repository"]["full_name"].split("/")
    owner = full_name[0]
    repo = full_name[1]
    sha = request_body["after"]

    ref = request_body["ref"]
    pusher = request_body["pusher"]["login"]
    full_name = request_body["pusher"]["full_name"]
    title = request_body["commits"][0]["message"]
    commit_url = request_body["commits"][0]["url"]

    return owner, repo, sha, ref, pusher, full_name, title, commit_url


def create_comment(file_name: str, diff_content: str, response: str) -> str:
    return f"文件名：{file_name} \n\r ## 审查结果：\n\r {response}"


def create_report_comment(file_name: str, diff_content: str, response: str) -> str:
    return f"\n\r## 文件名：{file_name} \n\r {response}"


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
