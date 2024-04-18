# Private Headstash Airdrop

### pulsar-3
**code-id: `4461`** \
**contract-address: ` `**

## Unaudited fork of [Shade Protocol](https://shadeprotocol.io/) contracts.


## Testing Workflow 

1. build contract 
```sh
make release
```
2. prepare headstash tools 
```sh
cd tools/headstash && yarn 
```
3. store contract 
```sh
cd ../../ && node tools/headstash/main -s
```

4. instantiate test tokens 
```sh
node tools/headstash/main -i 
```

5. instantiate headstash contract 
```sh 
node tools/headstash/main -a 
```

6. setup snip20's for the contract 
```sh
## TODO
```

7. fund contract with expected airdrop assets 
```sh

```

8. claim tokens by creating an account 
```sh

```