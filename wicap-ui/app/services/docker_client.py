import docker


def get_docker_client():
    try:
        return docker.from_env()
    except Exception:
        return None
