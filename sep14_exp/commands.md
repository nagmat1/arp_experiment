# Compile : 

```
 p4c --p4runtime-files basic.txt --target bmv2 --arch v1model arp_pl.p4
```

# Run1 :

```
simple_switch --log-console --interface 1@ens7 --interface 2@ens8 --interface 3@ens9 arp_pl.json
```

# Run2 :

```
simple_switch --log-console --interface 2@ens7 --interface 1@ens8 --interface 3@ens9 arp_pl.json
```

# Run3 : 

```
simple_switch --log-console --interface 3@ens7 --interface 2@ens8 --interface 1@ens9 arp_pl.json
```
