package:
	tar -czvf dist.tar.gz \
		cmd/ \
		pkg/ \
		site/ \
		docker-compose.yml \
		*.Dockerfile \
		go.mod go.sum \
		README.md
