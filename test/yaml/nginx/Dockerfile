FROM nginx:latest

ADD nginx.conf /etc/nginx/nginx.conf
ADD 4096 /usr/share/nginx/html/4096
ADD 2MB /usr/share/nginx/html/2MB
ADD 600 /usr/share/nginx/html/600

ENTRYPOINT ["nginx"]
