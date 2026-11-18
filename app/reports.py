"""Line counts for report files."""


def line_count(filename):
    with open(filename, "r") as f:
        return sum(1 for _ in f)
