import sys

def greet(name: str, times: int = 2) -> str:
    parts = []
    for i in range(times):
        parts.append(f"hello {name} #{i}")
    return "\n".join(parts)


class Counter:
    def __init__(self, start: int = 0) -> None:
        self.value = start

    def bump(self) -> int:
        self.value += 1
        return self.value


if __name__ == "__main__":
    print(greet("rea"))
