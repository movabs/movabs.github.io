UNAME = $(shell uname -s)

current_dir = $(shell pwd)

all: docker

docker:
	docker build -t jekyll .
	docker run -it --name jekyll -v $(current_dir):/src jekyll

docker_start:
	docker start -i jekyll

docker_run:
	docker exec -it jekyll bash

prune:
	docker system prune -a --volumes
