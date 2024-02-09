## Backing up a remote `tf state`:

```shell
tf state pull > ~/Config/states/<project>/tf-`date +%s`.state
```

terracognita will make a `tf state` as well as `tf` files:

```shell
 terracognita google --project <project> --tfstate vc.tfstate -i google_compute_firewall --region us-central1 --credentials /Users/ganggreentempertatum/.config/gcloud/legacy_credentials/ganggreentempertatum@cohere.com/adc.json
--hcl /tmp/firewall.tf
```
then you merge the states

`~/go/bin/tfmerge -o terraform.tfstate /tmp/vc.tfstate`

and push when ready

`tf state push terraform.tfstate`
