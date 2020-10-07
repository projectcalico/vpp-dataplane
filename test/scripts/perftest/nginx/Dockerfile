FROM nginx:latest

ADD nginx.conf /etc/nginx/nginx.conf
ADD test_4k /usr/share/nginx/html/test_4k.html
ADD test_4k /usr/share/nginx/html/4096
ADD test_2m /usr/share/nginx/html/2MB

ENTRYPOINT ["nginx"]
