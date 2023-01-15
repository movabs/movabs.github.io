from bretfisher/jekyll

RUN apt update && apt install -y git vim

COPY . /src

ENTRYPOINT [ "bash" ]
