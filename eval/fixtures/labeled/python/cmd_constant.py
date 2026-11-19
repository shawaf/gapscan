import subprocess


def build_docs():
    subprocess.run("make -C docs html", shell=True, check=True)


if __name__ == "__main__":
    build_docs()
