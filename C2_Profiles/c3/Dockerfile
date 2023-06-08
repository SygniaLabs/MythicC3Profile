FROM itsafeaturemythic/mythic_go_base:latest

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

RUN apk add --update make

COPY --from=0 /main /main
COPY --from=0 /mythic_c3_server /mythic_c3_server

WORKDIR /Mythic/

CMD make run