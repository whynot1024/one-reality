
1. 根据asn获取cidr

```shell
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169" | jq '.data.prefixes[].prefix'
```

2. get一个cidr对应的国家
  
  mmdb

然后就可以过滤出一个asn里面属于某个国家的cidr list
