from __future__ import annotations

import random
from queue import Empty, Queue
from threading import Event, Lock, Thread
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from constants import ROOT, SUPPORT, TIMEOUT, URL
from requests import HTTPError, Session


FLAG07 = "ec6610336fb27050498e2f0f42f2432e"

HIDDEN_URL = f"{URL}/.hidden/"

FLAG_PATH = SUPPORT / "flag07.txt"
READMES_DIR = ROOT / "readmes.nosync"
READMES_DIR.mkdir(exist_ok=True)

WORKERS: list[Worker] = []
N_THREADS = 10


def add_to_random_worker(file_url: str) -> None:
    random.choice(WORKERS).add_work(file_url)


def add_to_worker(worker_idx: int, file_url: str) -> None:
    WORKERS[worker_idx].add_work(file_url)


def save_file(file_url: str) -> None:
    start_idx = file_url.rfind("/") + 1

    if not (filename := file_url[start_idx:]):
        return

    filepath = READMES_DIR / filename

    if filepath.is_file():
        print(f"{filename!r} already exists, skipping")
        return

    response = requests.get(file_url, timeout=TIMEOUT)

    try:
        response.raise_for_status()
    except (HTTPError, TimeoutError):
        add_to_random_worker(file_url)

    with filepath.open("wb") as file:
        file.write(response.content)

    print(f"{filename!r} saved")


def check_if_scanned(link: str) -> bool:
    with Worker.lock:
        present = link in Worker.scanned_links
        Worker.scanned_links.add(link)
        return present


class Worker(Thread):
    n_requests = 0
    lock = Lock()
    target_links: set[str] = set()
    scanned_links: set[str] = set()

    def __init__(self, thread_id: int) -> None:
        super().__init__()
        self._stop_event = Event()
        self.queue: Queue[str] = Queue()
        self.thread_id = thread_id
        self.terminate = False
        self.session = Session()

    def add_work(self, file_url: str) -> None:
        self.queue.put(file_url)

    def stop(self) -> None:
        self.terminate = True
        self._stop_event.set()

    def get_all_file_urls(self, file_url: str) -> list[str]:
        response = self.session.get(file_url)

        with Worker.lock:
            Worker.n_requests += 1

        soup = BeautifulSoup(response.text, "html.parser")
        file_urls = [a["href"] for a in soup.find_all("a", href=True)]
        soup.decompose()

        file_urls = [
            urljoin(file_url, url) for url in file_urls if url != "../"
        ]
        return [
            file_url
            for file_url in file_urls
            if file_url not in Worker.scanned_links
        ]

    def run(self) -> None:
        while not self.terminate:
            try:
                file_url = self.queue.get(timeout=TIMEOUT)
            except Empty:
                self.stop()
                continue

            if file_url.startswith("/"):
                file_url = f"{HIDDEN_URL}{file_url}"

            if HIDDEN_URL not in file_url:
                continue
            if check_if_scanned(file_url):
                continue
            if not (file_urls := self.get_all_file_urls(file_url)):
                continue

            filtered_urls: list[str] = []

            for file_url in file_urls:
                if file_url in Worker.target_links:
                    continue

                Worker.target_links.add(file_url)
                filtered_urls.append(file_url)

                thread = Thread(
                    target=save_file, args=(file_url,), daemon=True
                )
                thread.start()

            for file_url in filtered_urls:
                add_to_random_worker(file_url)


def concatenate_readmes() -> None:
    readmes = sorted(READMES_DIR.glob("README*"))

    with FLAG_PATH.open("w", encoding="utf-8") as outfile:
        for inpath in readmes:
            with inpath.open(encoding="utf-8") as infile:
                outfile.write(infile.read())


def main() -> None:
    # for i in range(N_THREADS):
    #     WORKERS.append(Worker(i))

    # for worker in WORKERS:
    #     worker.start()

    # add_to_worker(0, HIDDEN_URL)

    # try:
    #     for worker in WORKERS:
    #         worker.join()
    # except KeyboardInterrupt:
    #     for worker in WORKERS:
    #         worker.stop()

    concatenate_readmes()


if __name__ == "__main__":
    main()
