FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
	gcc g++ git zlib1g-dev pciutils kmod \
	python3-pip
RUN pip3 install meson pyelftools ninja
RUN mkdir -p /scratch/patches

ADD patches/* /scratch/patches/

ADD build_script.sh /scratch/build_script.sh

CMD /scratch/build_script.sh


