$oldIpRule = "10.0.0.10"
$newIPsource = "10.0.0.29"
$newDestinationIp = "10.0.0.29"
$resourcgrp = "nsgmgmt"


$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourcgrp
$rule = $nsg | Get-AzNetworkSecurityRuleConfig
#get all rules with affected ips
$affectedRules = $rule | where { ($_.SourceAddressPrefix -match $oldIpRule) -or ($_.DestinationAddressPrefix -match $oldIpRule) }
$affectedRules | % {
    #get associated NSG
    $ResourceID = $_.ID
    $ResourceID = $ResourceID.Split("/");
    $AscNSG = $ResourceID[8]
    $AscNSG = Get-AzNetworkSecurityGroup -Name $AscNSG -ResourceGroupName $resourcgrp  

    
    $NSGSourceAddressPrefix = $_.SourceAddressPrefix
    $NSGDestinationAddressPrefix = $_.DestinationAddressPrefix
    if ($NSGSourceAddressPrefix -match $oldIpRule) {  
        if ($newIPsource) {
            $NSGSourceAddressPrefix += $newIPsource
        }
        $NSGSourceAddressPrefix = $NSGSourceAddressPrefix | ? { $_ -ne $oldIpRule }
        Set-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $AscNSG `
            -Name $_.name `
            -Access $_.Access `
            -Protocol $_.Protocol `
            -Direction $_.Direction `
            -Priority $_.Priority `
            -SourceAddressPrefix $NSGSourceAddressPrefix `
            -SourcePortRange $_.SourcePortRange `
            -DestinationAddressPrefix $_.DestinationAddressPrefix `
            -DestinationPortRange $_.DestinationPortRange 

        $AscNSG | Set-AzNetworkSecurityGroup
    }
    if ($NSGDestinationAddressPrefix -match $oldIpRule) {
        if ($newDestinationIp) {
            $NSGDestinationAddressPrefix += $newDestinationIp
        }
        $NSGDestinationAddressPrefix = $NSGDestinationAddressPrefix | ? { $_ -ne $oldIpRule }
        Set-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $AscNSG `
            -Name $_.name `
            -Access $_.Access `
            -Protocol $_.Protocol `
            -Direction $_.Direction `
            -Priority $_.Priority `
            -SourceAddressPrefix $_.SourceAddressPrefix `
            -SourcePortRange $_.SourcePortRange `
            -DestinationAddressPrefix $NSGDestinationAddressPrefix `
            -DestinationPortRange $_.DestinationPortRange 

        $AscNSG | Set-AzNetworkSecurityGroup

    }
}
    
