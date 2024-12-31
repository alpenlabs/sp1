#! /bin/bash

# Get the current git branch.
GIT_REF=$(git rev-parse --abbrev-ref HEAD)

# Define the list of CPU workloads.
CPU_WORKLOADS=(
    # "v4/chess"
    # "v4/fibonacci"
    # "v4/json"
    # "v4/regex"
    # "v4/rsp"
    # "v4/ssz-withdrawals"
    # "v4/tendermint"
)

# Define the list of CUDA workloads.
CUDA_WORKLOADS=(
    # "v4/chess"
    # "v4/fibonacci"
    # "v4/json"
    # "v4/regex"
    # "v4/rsp"
    # "v4/ssz-withdrawals"
    # "v4/tendermint"
)

# Define the list of network workloads.
NETWORK_WORKLOADS=(
   "v4/blobstream-10331-11001"
   "v4/blobstream-10476-10547"
   "v4/blobstream-10552-10820"
   "v4/blobstream-10666-10849"
   "v4/blobstream-10873-11833"
   "v4/blobstream-10983-11478"
   "v4/blobstream-11220-11619"
   "v4/blobstream-11297-12243"
   "v4/blobstream-11393-11455"
   "v4/blobstream-1144-1235"
   "v4/blobstream-11509-12149"
   "v4/blobstream-11526-12448"
   "v4/blobstream-11688-12155"
   "v4/blobstream-1211-1249"
   "v4/blobstream-12130-12394"
   "v4/blobstream-1238-2149"
   "v4/blobstream-12532-12763"
   "v4/blobstream-1257-1835"
   "v4/blobstream-12620-13504"
   "v4/blobstream-12987-13378"
   "v4/blobstream-13361-13965"
   "v4/blobstream-13375-14264"
   "v4/blobstream-1380-2098"
   "v4/blobstream-13967-14032"
   "v4/blobstream-14166-14647"
   "v4/blobstream-14446-14985"
   "v4/blobstream-14480-14869"
   "v4/blobstream-14490-14607"
   "v4/blobstream-14625-14821"
   "v4/blobstream-15108-15559"
   "v4/blobstream-15795-16380"
   "v4/blobstream-17176-17190"
   "v4/blobstream-17346-17579"
   "v4/blobstream-1784-1991"
   "v4/blobstream-17854-18628"
   "v4/blobstream-18108-18990"
   "v4/blobstream-18254-19020"
   "v4/blobstream-1847-2176"
   "v4/blobstream-18509-18920"
   "v4/blobstream-1864-2105"
   "v4/blobstream-18820-19529"
   "v4/blobstream-1918-2761"
   "v4/blobstream-19477-19767"
   "v4/blobstream-19646-20138"
   "v4/blobstream-19651-19705"
   "v4/blobstream-2048-3048"
   "v4/blobstream-224-735"
   "v4/blobstream-2285-2391"
   "v4/blobstream-2326-2695"
   "v4/blobstream-2372-3155"
   "v4/blobstream-3107-3544"
   "v4/blobstream-3448-4438"
   "v4/blobstream-3541-4011"
   "v4/blobstream-4071-4323"
   "v4/blobstream-4111-4575"
   "v4/blobstream-4145-4955"
   "v4/blobstream-4209-5050"
   "v4/blobstream-4472-4730"
   "v4/blobstream-4609-5541"
   "v4/blobstream-4644-5079"
   "v4/blobstream-4671-5497"
   "v4/blobstream-4796-5466"
   "v4/blobstream-4817-5259"
   "v4/blobstream-5051-5469"
   "v4/blobstream-5061-5958"
   "v4/blobstream-5202-5805"
   "v4/blobstream-5289-5877"
   "v4/blobstream-5480-6102"
   "v4/blobstream-5482-6230"
   "v4/blobstream-5725-6605"
   "v4/blobstream-576-1544"
   "v4/blobstream-5808-6763"
   "v4/blobstream-583-1315"
   "v4/blobstream-590-1210"
   "v4/blobstream-6027-6921"
   "v4/blobstream-627-964"
   "v4/blobstream-6297-6712"
   "v4/blobstream-6369-6979"
   "v4/blobstream-6370-7053"
   "v4/blobstream-6378-7064"
   "v4/blobstream-6420-6501"
   "v4/blobstream-6491-7323"
   "v4/blobstream-6551-6586"
   "v4/blobstream-656-1533"
   "v4/blobstream-6599-7086"
   "v4/blobstream-6637-7604"
   "v4/blobstream-6754-7168"
   "v4/blobstream-6775-7063"
   "v4/blobstream-6945-7480"
   "v4/blobstream-7144-7203"
   "v4/blobstream-729-1184"
   "v4/blobstream-7356-7984"
   "v4/blobstream-7364-7576"
   "v4/blobstream-7528-8446"
   "v4/blobstream-7806-8758"
   "v4/blobstream-8059-9043"
   "v4/blobstream-8228-9162"
   "v4/blobstream-8239-9109"
   "v4/blobstream-8366-9145"
   "v4/blobstream-8368-8370"
   "v4/blobstream-8581-9358"
   "v4/blobstream-8649-9142"
   "v4/blobstream-8934-9690"
   "v4/blobstream-9217-10050"
   "v4/blobstream-9406-10330"
   "v4/blobstream-958-1141"
   "v4/blobstream-9735-9883"
   "v4/blobstream-9837-10292"
   "v4/blobstream-9941-10566"
   "v4/blobstream-9960-10420"
   "v4/chess"
   "v4/fibonacci"
   "v4/json"
   "v4/regex"
   "v4/rsp"
   "v4/ssz-withdrawals"
   "v4/tendermint"
   "v4/vector-10028-10751"
   "v4/vector-10575-10942"
   "v4/vector-10983-11740"
   "v4/vector-11972-12036"
   "v4/vector-12294-12988"
   "v4/vector-13400-14122"
   "v4/vector-13407-13524"
   "v4/vector-1374-2341"
   "v4/vector-13822-14726"
   "v4/vector-14013-14621"
   "v4/vector-14070-15006"
   "v4/vector-14242-14254"
   "v4/vector-14298-14423"
   "v4/vector-14918-15658"
   "v4/vector-1519-1555"
   "v4/vector-15544-15942"
   "v4/vector-15992-16388"
   "v4/vector-16434-16718"
   "v4/vector-16495-17244"
   "v4/vector-1676-1691"
   "v4/vector-16766-17427"
   "v4/vector-16974-17753"
   "v4/vector-17692-18269"
   "v4/vector-17730-18329"
   "v4/vector-17806-18019"
   "v4/vector-17922-18776"
   "v4/vector-17959-18724"
   "v4/vector-18507-19337"
   "v4/vector-18964-19165"
   "v4/vector-19220-19874"
   "v4/vector-19456-19572"
   "v4/vector-19495-19727"
   "v4/vector-19552-20431"
   "v4/vector-20118-21085"
   "v4/vector-20754-21232"
   "v4/vector-21244-22003"
   "v4/vector-21513-21709"
   "v4/vector-21553-22504"
   "v4/vector-21655-22085"
   "v4/vector-2174-2688"
   "v4/vector-21748-22502"
   "v4/vector-22110-22501"
   "v4/vector-22113-22170"
   "v4/vector-22266-22712"
   "v4/vector-22506-23291"
   "v4/vector-22644-23303"
   "v4/vector-23168-24082"
   "v4/vector-23589-23936"
   "v4/vector-24463-24490"
   "v4/vector-24574-24630"
   "v4/vector-24649-25231"
   "v4/vector-24870-25828"
   "v4/vector-25089-25128"
   "v4/vector-25322-25570"
   "v4/vector-25372-26146"
   "v4/vector-25536-25579"
   "v4/vector-25576-26246"
   "v4/vector-2640-2873"
   "v4/vector-26410-27116"
   "v4/vector-26565-26590"
   "v4/vector-26698-26837"
   "v4/vector-2677-3329"
   "v4/vector-26830-27571"
   "v4/vector-27343-27474"
   "v4/vector-27520-28181"
   "v4/vector-27833-28655"
   "v4/vector-28340-28600"
   "v4/vector-28557-29239"
   "v4/vector-28872-29142"
   "v4/vector-29053-29833"
   "v4/vector-29263-29384"
   "v4/vector-2954-3721"
   "v4/vector-29649-30646"
   "v4/vector-29798-30561"
   "v4/vector-30014-30264"
   "v4/vector-30323-31318"
   "v4/vector-30336-30973"
   "v4/vector-3080-3695"
   "v4/vector-3111-3632"
   "v4/vector-31262-32035"
   "v4/vector-31408-31492"
   "v4/vector-31561-32087"
   "v4/vector-32033-32702"
   "v4/vector-32045-32056"
   "v4/vector-32216-32437"
   "v4/vector-3561-3816"
   "v4/vector-3695-4546"
   "v4/vector-3814-3943"
   "v4/vector-4263-4696"
   "v4/vector-4457-4705"
   "v4/vector-4579-5414"
   "v4/vector-4730-5428"
   "v4/vector-4890-5540"
   "v4/vector-51-679"
   "v4/vector-517-1360"
   "v4/vector-5249-6054"
   "v4/vector-5750-5949"
   "v4/vector-5763-6083"
   "v4/vector-5764-5923"
   "v4/vector-5809-5925"
   "v4/vector-6002-6824"
   "v4/vector-6146-6195"
   "v4/vector-6212-6306"
   "v4/vector-6387-6498"
   "v4/vector-699-1432"
   "v4/vector-713-1021"
   "v4/vector-7552-8283"
   "v4/vector-9201-9801"
   "v4/vector-9482-9834"
   "v4/vector-9844-10412"
)

# Create a JSON object with the list of workloads.
WORKLOADS=$(jq -n \
    --arg cpu "$(printf '%s\n' "${CPU_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg cuda "$(printf '%s\n' "${CUDA_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg network "$(printf '%s\n' "${NETWORK_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    '{cpu_workloads: $cpu, cuda_workloads: $cuda, network_workloads: $network}')

# Run the workflow with the list of workloads.
echo $WORKLOADS | gh workflow run suite.yml --ref $GIT_REF --json
