import os
import time


def get_used_memory():
    mem_info = os.popen('free -m').readlines()[1].split()[2]
    return int(mem_info)


def monitor_memory(interval=1):
    initial_memory = get_used_memory()
    max_memory = initial_memory

    print(f"Initial used memory: {initial_memory} MB")

    while True:
        current_memory = get_used_memory()

        if current_memory > max_memory:
            max_memory = current_memory

        print(f"Maximum used memory so far: {max_memory-initial_memory} MB")

        time.sleep(interval)


if __name__ == "__main__":
    monitor_memory(interval=1)