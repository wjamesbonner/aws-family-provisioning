param(
    [Alias("s")]
    [string] $serviceFamily = "",

    [Alias("st")]
    [string] $serviceFamilyTagName = "service-family",

    [Alias("c")]
    [string] $cidrBlock  = "10.1.1.0/24",

    [Alias("t")]
    [string] $instanceTenancy   = "default",

    [Alias("n")]
    [string[]] $networks  = @("10.1.1.0/25", "10.1.1.128/25"),

    [Alias("z")]
    [string[]] $zones  = @("us-west-2a", "us-west-2b"),

    [Alias("m")]
    [string] $managementMode  = "automatic",

    [Alias("mt")]
    [string] $managementModeTagName  = "management-mode",

    [Alias("e")]
    [string] $environment  = "production",

    [Alias("et")]
    [string] $environmentTagName  = "environment",

    [Alias("p")]
    [string] $profileName  = "",

    [Alias("elb")]
    [bool] $loadBalancer = $false,

    [Alias("app")]
    [string] $applicationType = "web",

    [Alias("ecr")]
    [bool] $containerRepository = $false,

    [Alias("ecs")]
    [bool] $containerCluster = $false,

    [Alias("h")]
    [switch] $help = $false
)

if ($help) {
    Write-Output ("`t aws_provision_service_family.ps1 will create and configure a VPC environment for a new service, and tag all resources for simple management.")
    Write-Output ("`t Prerequisites: Powershell, AWS CLI, AWS.Tools for Powershell")
    Write-Output ("`t ")
    Write-Output ("`t Parameters:")
    Write-Output ("`t ")
    Write-Output ("`t serviceFamily")
    Write-Output ("`t     The name of the service family.")
    Write-Output ("`t     Default: {0}" -f $serviceFamily)
    Write-Output ("`t     Alias: s")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -serviceFamily {0}" -f $serviceFamily)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -s {0}" -f $serviceFamily)
	
    Write-Output ("`t ")
    Write-Output ("`t serviceFamilyTagName")
    Write-Output ("`t     The name of the tag that stores the service family name")
    Write-Output ("`t     Default: {0}" -f $serviceFamilyTagName)
    Write-Output ("`t     Alias: st")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -serviceFamilyTagName service-family")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -st service-family")

    Write-Output ("`t ")
    Write-Output ("`t cidrBlock")
    Write-Output ("`t     The CIDR block to use for this VPC")
    Write-Output ("`t     Default: {0}" -f $cidrBlock)
    Write-Output ("`t     Alias: c")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -cidrBlock {0}" -f $cidrBlock)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -c {0}" -f $cidrBlock)

    Write-Output ("`t ")
    Write-Output ("`t instanceTenancy")
    Write-Output ("`t     The default tenancy for this VPC, i.e. dedicated hosting versus shared hosting.")
    Write-Output ("`t     Default: {0}" -f $instanceTenancy)
    Write-Output ("`t     Alias: t")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -instanceTenancy {0}" -f $instanceTenancy)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -t {0}" -f $instanceTenancy)

    Write-Output ("`t ")
    Write-Output ("`t networks")
    Write-Output ("`t     Array of networks to define in the VPC CIDR block.  Must positionally match the zones parameter.")
    Write-Output ("`t     Default: {0}" -f $networks)
    Write-Output ("`t     Alias: n")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -networks {0}" -f $networks)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -n {0}" -f $networks)

    Write-Output ("`t ")
    Write-Output ("`t zones")
    Write-Output ("`t     The zones to to place the subnets in; corresponds positionally to the subnetworks parameter")
    Write-Output ("`t     Default: {0}" -f $zones)
    Write-Output ("`t     Alias: z")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -zones {0}" -f $zones)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -z {0}" -f $zones)

    Write-Output ("`t ")
    Write-Output ("`t environment")
    Write-Output ("`t     The environment of the service, e.g., production or staging.")
    Write-Output ("`t     Default: {0}" -f $environment)
    Write-Output ("`t     Alias: e")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -environment {0}" -f $environment)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -e {0}" -f $environment)

    Write-Output ("`t ")
    Write-Output ("`t environmentTagName")
    Write-Output ("`t     The name of the tag that stores the environment")
    Write-Output ("`t     Default: {0}" -f $environmentTagName)
    Write-Output ("`t     Alias: et")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -environmentTagName {0}" -f $environmentTagName)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -et {0}" -f $environmentTagName)

    Write-Output ("`t ")
    Write-Output ("`t profileName")
    Write-Output ("`t     The name of the AWS configure credential profile to use, leave empty for default.")
    Write-Output ("`t     Default: {0}" -f $profileName)
    Write-Output ("`t     Alias: p")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -profileName {0}" -f "myProfile")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -p {0}" -f "myProfile")

    Write-Output ("`t ")
    Write-Output ("`t loadBalancer")
    Write-Output ("`t     Indicates whether to provision a load balancer for the environment.")
    Write-Output ("`t     Default: {0}" -f $loadBalancer)
    Write-Output ("`t     Alias: elb")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -loadBalancer {0}" -f $loadBalancer)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -elb {0}" -f $loadBalancer)

    Write-Output ("`t ")
    Write-Output ("`t application")
    Write-Output ("`t     Indicates the type of application used by the service to tailor the environment.")
    Write-Output ("`t     Default: {0}" -f $application)
    Write-Output ("`t     Alias: app")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -application {0}" -f $application)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -app {0}" -f $application)

    Write-Output ("`t ")
    Write-Output ("`t containerRepository")
    Write-Output ("`t     Indicates whether to provision a container repository for the environment.")
    Write-Output ("`t     Default: {0}" -f $containerRepository)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -containerRepository {0}" -f $containerRepository)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -ecr {0}" -f $containerRepository)

    Write-Output ("`t ")
    Write-Output ("`t containerCluster")
    Write-Output ("`t     Indicates whether to provision a container repository for the environment.")
    Write-Output ("`t     Default: {0}" -f $containerRepository)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -containerRepository {0}" -f $containerCluster)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -ecs {0}" -f $containerCluster)

    Write-Output ("`t ")
    Write-Output ("`t managementMode")
    Write-Output ("`t     The management mode of the service, i.e. automatic or manual")
    Write-Output ("`t     Default: {0}" -f $managementMode)
    Write-Output ("`t     Alias: m")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -managementMode {0}" -f $managementMode)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -m {0}" -f $managementMode)

    Write-Output ("`t ")
    Write-Output ("`t managementModeTagName")
    Write-Output ("`t     The name of the tag that stores the management mode tag name")
    Write-Output ("`t     Default: {0}" -f $managementModeTagName)
    Write-Output ("`t     Alias: mt")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -managementModeTagName {0}" -f $managementModeTagName)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -mt {0}" -f $managementModeTagName)

    Write-Output ("`t ")
    Write-Output ("`t profileName")
    Write-Output ("`t     The name of AWS configure profile to use for account access")
    Write-Output ("`t     Default: {0}" -f $profileName)
    Write-Output ("`t     Alias: p")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -profileName {0}" -f $profileName)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -p {0}" -f $profileName)

    Write-Output ("`t ")
    Write-Output ("`t loadBalancer")
    Write-Output ("`t     Indicates whether to build a generic load balancer for the service environment")
    Write-Output ("`t     Default: {0}" -f $loadBalancer)
    Write-Output ("`t     Alias: elb")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -loadBalancer {0}" -f $loadBalancer)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -elb {0}" -f $loadBalancer)

    Write-Output ("`t ")
    Write-Output ("`t containerRepository")
    Write-Output ("`t     Indicates whether to build a generic container repository for the service environment")
    Write-Output ("`t     Default: {0}" -f $containerRepository)
    Write-Output ("`t     Alias: ecr")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -loadBalancer {0}" -f $containerRepository)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -elb {0}" -f $containerRepository)

    Write-Output ("`t ")
    Write-Output ("`t containerCluster")
    Write-Output ("`t     Indicates whether to build a generic container cluster for the service environment, with ASG, LC, capacity plan")
    Write-Output ("`t     Default: {0}" -f $containerCluster)
    Write-Output ("`t     Alias: ecs")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -loadBalancer {0}" -f $containerCluster)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -elb {0}" -f $containerCluster)

    Write-Output ("`t ")
    Write-Output ("`t applicationType")
    Write-Output ("`t     Makes minor customizations for supported application types.  Supported type(s) is: web")
    Write-Output ("`t     Default: {0}" -f $applicationType)
    Write-Output ("`t     Alias: app")
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -applicationType {0}" -f $applicationType)
    Write-Output ("`t     Example: .\aws_provision_service_family.ps1 -app {0}" -f $applicationType)

    return $false
}

if($networks.Length -ne $zones.Length) {
    Write-Output "`t The number of subnetworks must match the number of zones"
    return $false
}

# Prompt for name if not specified
if ($serviceFamily -eq "") {
	$serviceFamily = Read-Host "Enter the name of the service family"
}
$serviceFamily = $serviceFamily.ToLower()

# Prompt for environment if not valid value
if ($environment -ne "production" -and $environment -ne "staging") {
	$environment = Read-Host "Enter a valid environment [production or staging]"
}
$environment = $environment.ToLower()

# Check if custom aws credential profile is specified
if($profileName -ne "") {
    try {
        Set-AWSCredential -ProfileName $profileName
        Write-Output ("`t AWS Profile set to {0}!" -f $profileName)
    } catch {
        Write-Output "`t Failed to set specified profile - aborting."
        return $false
    }
}

# navigate to library root
cd $PSScriptRoot

$transcriptName = ("aws_provision_service_family-{0}.transcript" -f [DateTimeOffset]::Now.ToUnixTimeSeconds())
Start-Transcript -Path $transcriptName

$serviceFamily
$serviceFamilyTagName
$cidrBlock
$instanceTenancy
$networks
$zones
$managementMode

# load necessary modules
.\aws_load_default_modules.ps1

# Checking for existing VPC with service family
Write-Output ""
Write-Output "`t Searching for conflicting service family VPCs."
Write-Output "`t Building tag filters and retrieving tags..."
$filters = @()
$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "resource-type"
$filter.Values.Add("vpc")
$filters += $filter

$filter = New-Object -TypeName Amazon.EC2.Model.Filter
$filter.Name = "tag:service-family"
$filter.Values.Add($serviceFamily)
$filters += $filter
$vpcTags = Get-EC2Tag -Filter $filters

if($vpcTags -ne $null) {
    Write-Output "`t Service already exists - aborting!"
    Stop-Transcript
    return $false
}

# Prepare tags for to apply to resources as they are created
Write-Output "`t Building environment tags..."
$hash = @{Key="Name"; Value=$serviceFamily}
$nameTag = [PSCustomObject]$hash
$nameTag

$hash = @{Key=$serviceFamilyTagName; Value=$serviceFamily}
$serviceTag = [PSCustomObject]$hash
$serviceTag

$hash = @{Key=$managementModeTagName; Value=$managementMode}
$managementTag = [PSCustomObject]$hash
$managementTag

$hash = @{Key=$environmentTagName; Value=$environment}
$environmentTag = [PSCustomObject]$hash
$environmentTag

# Creating the virtual private cloud
Write-Output ""
Write-Output "`t Begin building and configuring the virtual private cloud."
Write-Output "`t Creating VPC..."
$vpc = New-EC2VPC -CidrBlock $cidrBlock -InstanceTenancy $instanceTenancy
$vpc

do{
    Write-Output ("`t Checking VPC {0} state..." -f $vpc.VpcId)
    $vpc = Get-EC2Vpc -VpcId $vpc.VpcId
    Start-Sleep -Seconds 5
} while($vpc.State -ne "available")

Write-Output "`t Enabling VPC DNS hostnames..."
Edit-EC2VpcAttribute -VpcId $vpc.VpcId -EnableDnsHostname $true

Write-Output "`t Tagging VPC..."
New-EC2Tag -Resource $vpc.VpcId -Tag $nameTag
New-EC2Tag -Resource $vpc.VpcId -Tag $serviceTag
New-EC2Tag -Resource $vpc.VpcId -Tag $managementTag
New-EC2Tag -Resource $vpc.VpcId -Tag $environmentTag

Write-Output "`t Building subnets..."
$subnets = @()
for($i=0;$i -lt $networks.Length;$i++) {
    $subnet = New-EC2Subnet -VpcId $vpc.VpcId -CidrBlock $networks[$i] -AvailabilityZone $zones[$i]
    $subnet
    do{
        Write-Output ("`t Checking subnet {0} state..." -f $subnet.CidrBlock)
        $subnet = Get-EC2Subnet -SubnetId $subnet.SubnetId
        $subnet
        Start-Sleep -Seconds 5
    } while($subnet.State -ne "available")

    Write-Output "`t Tagging subnet..."
    New-EC2Tag -Resource $subnet.SubnetId -Tag $nameTag
    New-EC2Tag -Resource $subnet.SubnetId -Tag $serviceTag
    New-EC2Tag -Resource $subnet.SubnetId -Tag $managementTag
    New-EC2Tag -Resource $subnet.SubnetId -Tag $environmentTag
    $subnets += $subnet
}

# For use in subsequent steps
$subnetList = ($subnets | Select-Object -Expand SubnetId)

# Creating the internet gateway
Write-Output ""
Write-Output "`t Begin building and configuring the internet gateway."
Write-Output "`t Creating internet gateway..."
$igw = New-EC2InternetGateway
$igw

Write-Output "`t Tagging internet gateway..."
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $nameTag
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $serviceTag
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $managementTag
New-EC2Tag -Resource $igw.InternetGatewayId -Tag $environmentTag

Write-Output "`t Attaching internet gateway to VPC..."
Add-EC2InternetGateway -VpcId $vpc.VpcId -InternetGatewayId $igw.InternetGatewayId

do{
    Write-Output "`t Verifying IGW-VPC attachment..."
    do{
        Write-Output "`t Checking IGW-VPC attachment..."
        $igw = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId
        $igw
        Start-Sleep -Seconds 5
    } while($igw.Attachments.Count -ne 1)

    Write-Output "`t Checking IGW-VPC attachment status..."
    $igw = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId
    $igw
    Start-Sleep -Seconds 5
} while($igw.Attachments[0].VpcId -ne $vpc.VpcId -and $igw.Attachments[0].State -ne "available")

Write-Output "`t Internet gateway built, configured, and attached to VPC."
Write-Output ""

Write-Output "`t Retrieving route tables..."
$routeTables = Get-EC2RouteTable
$routeTables
foreach($routeTable in $routeTables) {
    if($routeTable.VpcId -eq $vpc.VpcId) {
        Write-Output "`t Tagging route tables..."
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $nameTag
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $serviceTag
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $managementTag
        New-EC2Tag -Resource $routeTable.RouteTableId -Tag $environmentTag

        Write-Output "`t Registering subnets to route table..."
        foreach($subnet in $subnets) {
            Register-EC2RouteTable -RouteTableId $routeTable.RouteTableId -SubnetId $subnet.SubnetId
        }

        Write-Output "`t Creating default IGW route..."
        New-EC2Route -RouteTableId $routeTable.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $igw.InternetGatewayId
    }
}
Write-Output "`t VPC built, configured, and tagged."
Write-Output ""

# Creating security group for load balancer
Write-Output ""
Write-Output "`t Begin building and configuring the ELB security group."
Write-Output "`t Creating load balancer security group..."
$sg = New-EC2SecurityGroup -GroupName $serviceFamily -Description $serviceFamily -VpcId $vpc.VpcId
$sg

Write-Output "`t Defining IP ranges and default egress rules..."
$ipRange = New-Object -TypeName Amazon.EC2.Model.IpRange
$ipRange.CidrIp = "0.0.0.0/0"
#$ipRange.Description = $null   # Do not set description or it will not match default egress rule.  
                                # Powershell differentiates null and parameter not set. 
                                # https://stackoverflow.com/questions/28697349/how-do-i-assign-a-null-value-to-a-variable-in-powershell
$ipRange

Write-Output "`t Building security group ingress rules..."
$httpPermission = New-Object -TypeName Amazon.EC2.Model.IpPermission
$httpPermission.FromPort = 80
$httpPermission.IpProtocol = "tcp"
$httpPermission.Ipv4Ranges = $ipRange
$httpPermission.ToPort = 80
$httpPermission

$httpsPermission = New-Object -TypeName Amazon.EC2.Model.IpPermission
$httpsPermission.FromPort = 443
$httpsPermission.IpProtocol = "tcp"
$httpsPermission.Ipv4Ranges = $ipRange
$httpsPermission.ToPort = 443
$httpsPermission

Write-Output "`t Applying ingress rules..."
Grant-EC2SecurityGroupIngress -GroupId $sg -IpPermission $httpPermission,$httpsPermission

# If a container cluster is built, we must leave outbound egress to allow for EC2 instances to register with global ECS service broker
if($containerCluster -eq $false) {
    Write-Output "`t Revoking default egress rules..."
    $outPermission = New-Object -TypeName Amazon.EC2.Model.IpPermission
    $outPermission.FromPort = 0
    $outPermission.IpProtocol = "-1"
    $outPermission.Ipv4Ranges = $ipRange
    $outPermission.ToPort = 0
    $outPermission

    Revoke-EC2SecurityGroupEgress -GroupId $sg -IpPermission $outPermission
}

Write-Output "`t Applying new security group egress rules..."
Grant-EC2SecurityGroupEgress -GroupId $sg -IpPermission $httpPermission,$httpsPermission

Write-Output "`t Tagging security group..."
New-EC2Tag -Resource $sg -Tag $nameTag
New-EC2Tag -Resource $sg -Tag $serviceTag
New-EC2Tag -Resource $sg -Tag $managementTag
New-EC2Tag -Resource $sg -Tag $environmentTag

Write-Output "`t Security group created, configured, and tagged."
Write-Output ""

if($loadBalancer) {
    # Creating the load balancer
    Write-Output ""
    Write-Output "`t Begin creation and configuration of load balancer."
    Write-Output "`t Creating elastic load balancer..."
    $elb = New-ELB2LoadBalancer -IpAddressType ipv4 -Name $serviceFamily -Scheme internet-facing -SecurityGroup $sg -Subnet $subnetList -Tag $nameTag,$serviceTag -Type application
    $elb

    do{
        Write-Output "`t Checking ELB state..."
        $elb = Get-ELB2LoadBalancer -LoadBalancerArn $elb.LoadBalancerArn
        Start-Sleep -Seconds 5
    } while($elb.State.Code -ne "active")

    Write-Output "`t Tagging ELB..."
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $nameTag
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $serviceTag
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $managementTag
    Add-ELB2Tag -ResourceArn  $elb.LoadBalancerArn -Tag $environmentTag

    if($containerCluster -and $applicationType -eq "web") {
        Write-Output "`t Creating web group target..."
        $elbTargetGroupParams = @{ 
            'Name'                       = $serviceFamily;
            'HealthCheckEnabled'         = $true;
            'HealthCheckIntervalSecond'  = 10;
            'HealthCheckTimeoutSecond'   = 5;
            'HealthyThresholdCount'      = 2;
            'Port'                       = 80;
            'Protocol'                   = 'HTTP';
            'TargetType'                 = 'instance';
            'UnhealthyThresholdCount'    = 2;
            'VpcId'                      = $vpc.VpcId;
        }

        $elbTargetGroup = New-ELB2TargetGroup @elbTargetGroupParams

        Write-Output "`t Tagging ELB target group..."
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $nameTag
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $serviceTag
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $managementTag
        Add-ELB2Tag -ResourceArn  $elbTargetGroup.TargetGroupArn -Tag $environmentTag

        Write-Output "`t Creating http listener..."
        $listenerTargetGroupTuple = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.TargetGroupTuple
        $listenerTargetGroupTuple.TargetGroupArn = $elbTargetGroup.TargetGroupArn
        $listenerTargetGroupTuple.Weight = 1
        
        $listenerTargetGroupStickiness = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.TargetGroupStickinessConfig
        $listenerTargetGroupStickiness.DurationSeconds = 300
        $listenerTargetGroupStickiness.Enabled = $false

        $listenerForwardAction = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.ForwardActionConfig
        $listenerForwardAction.TargetGroups = $listenerTargetGroupTuple
        $listenerForwardAction.TargetGroupStickinessConfig = $listenerTargetGroupStickiness

        $listenerAction = New-Object -TypeName Amazon.ElasticLoadBalancingV2.Model.Action
        $listenerAction.ForwardConfig = $listenerForwardAction
        $listenerAction.Order = 1
        $listenerAction.TargetGroupArn = $elbTargetGroup.TargetGroupArn
        $listenerAction.Type = "Forward"

        $elbHttpListener = @{
            'LoadBalancerArn'            = $elb.LoadBalancerArns;
            'DefaultAction'              = $listenerAction;
            'Port'                       = 80;
            'Protocol'                   = 'HTTP';
        }

        $elbListener = New-ELB2Listener @elbHttpListener
        $elbListener
    }

    Write-Output "`t ELB created, tagged and active."
    Write-Output ""
}

if($containerCluster) {
    # Creating EC2 Key Pair
    Write-Output ""
    Write-Output "`t Begin creation and configuration of EC2 SSH Key Pair."
    Write-Output "`t Checking for conflicting key..."

    if (Test-Path("{0}-ec2Key.fingerprint" -f $serviceFamily)) {
        rm ("{0}-ec2Key.fingerprint" -f $serviceFamily)
    }

    if (Test-Path("{0}-ec2Key.pem" -f $serviceFamily)) {
        rm ("{0}-ec2Key.pem" -f $serviceFamily)
    }

    $ec2Key = $null
    try {
        $ec2Key = Get-EC2KeyPair -KeyName $serviceFamily
    } catch {
        $ec2Key = $null
    }

    if($ec2Key -eq $null) {
        $ec2Key = New-EC2KeyPair -KeyName $serviceFamily
        $ec2Key.KeyFingerprint | Out-File -FilePath ("{0}-ec2Key.fingerprint" -f $serviceFamily)
        $ec2Key.KeyMaterial | Out-File -FilePath ("{0}-ec2Key.pem" -f $serviceFamily)
        Write-Output "`t EC2 Key created."
    } else {
        Write-Output "`t EC2 key already exists or failed to be created."
    }

    Write-Output "`t EC2 Key stage complete, "
    Write-Output ""

    $blockDeviceMap = New-Object -TypeName Amazon.AutoScaling.Model.BlockDeviceMapping
    $blockDeviceMap.DeviceName = '/dev/xvdcz'

    $blockDeviceMap.Ebs = New-Object -TypeName Amazon.AutoScaling.Model.Ebs
    $blockDeviceMap.Ebs.VolumeSize = 22;
    $blockDeviceMap.Ebs.VolumeType = 'gp2';
    $blockDeviceMap.Ebs.Encrypted = $true;
    $blockDeviceMap.Ebs.DeleteOnTermination = $true;

    $userData = ('#!/bin/bash
echo ECS_CLUSTER={0} >> /etc/ecs/ecs.config;echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config;' -f $serviceFamily)
    $userData = [System.Text.Encoding]::UTF8.GetBytes($userData)
    $userData = [System.Convert]::ToBase64String($userData)

    #$imageId = (Get-SSMParameter -Name /aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 -region 'us-west-2').Value
    $imageId = ((Get-SSMParameter -Name /aws/service/ecs/optimized-ami/amazon-linux-2/recommended -region 'us-west-2').Value | ConvertFrom-Json).image_id
    $imageId

    if($imageId -eq $null) {
        Write-Output "`t Failed to retrieve valid AMI image."
        Stop-Transcript
        return $false
    }

    $iamRoleParams = @{ 
        'Path'                       = '/';
        'RoleName'                   = ("{0}-EcsCluster-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'AssumeRolePolicyDocument'   = '{"Version":"2008-10-17","Statement":[{"Sid":"","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}';
        'Tag'                        = $nameTag,$serviceTag,$managementTag,$environmentTag;
    }
    $iamRole = New-IAMRole @iamRoleParams
    $iamRole

    if($iamRole -eq $null) {
        Write-Output "`t Failed to create role."
        Stop-Transcript
        return $false
    }

    $iamRolePolicyParams = @{ 
        'RoleName'                   = $iamRole.RoleName;
        'PolicyArn'                  = 'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role';
    }
    $iamRolePolicy = Register-IAMRolePolicy @iamRolePolicyParams
    $iamRolePolicy

    $iamInstanceProfileParams = @{ 
        'InstanceProfileName'        = $iamRole.RoleName;
        'Path'                       = '/';
    }
    $iamInstanceProfile = New-IAMInstanceProfile @iamInstanceProfileParams
    $iamInstanceProfile = Add-IAMRoleToInstanceProfile -InstanceProfileName $iamRole.RoleName -RoleName $iamRole.RoleName
    $iamInstanceProfile = Get-IAMInstanceProfile -InstanceProfileName $iamRole.RoleName
    $iamInstanceProfile

    # Wait for Profile ARN to propogate in AWS backend
    Start-Sleep -Seconds 30

    $asLaunchConfigurationParams = @{ 
        'LaunchConfigurationName'    = ("EC2ContainerService-{0}-EcsInstanceLc-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'InstanceType'               = 't3a.medium';
        'ImageId'                    = $imageId;
        'KeyName'                    = $serviceFamily;
        'AssociatePublicIpAddress'   = $true;
        'BlockDeviceMapping'         = $blockDeviceMap;
        'IamInstanceProfile'         = $iamInstanceProfile.Arn;
        'InstanceMonitoring_Enabled' = $true;
        'SecurityGroup'              = $sg;
        'UserData'                   = $userData;
    }
    New-ASLaunchConfiguration @asLaunchConfigurationParams
    $asLaunchConfiguration = Get-ASLaunchConfiguration -LaunchConfigurationName $asLaunchConfigurationParams.LaunchConfigurationName

    $asAutoScalingGroupParams = @{ 
        'AutoScalingGroupName'             = ("EC2ContainerService-{0}-EcsInstanceAsg-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'LaunchConfigurationName'          = $asLaunchConfiguration.LaunchConfigurationName;
        'MinSize'                          = 2;
        'MaxSize'                          = 2;
        'AvailabilityZone'                 = $zones;
        'DefaultCooldown'                  = 300;
        'DesiredCapacity'                  = 2;
        'NewInstancesProtectedFromScaleIn' = $true;
        'Tag'                              = $nameTag,$serviceTag,$managementTag,$environmentTag;
        'TargetGroupARNs'                  = $elbTargetGroup.TargetGroupArn;
        'VPCZoneIdentifier'                = ($subnetList -join ',');
    }
    New-ASAutoScalingGroup @asAutoScalingGroupParams
    $asAutoScalingGroup = Get-ASAutoScalingGroup -AutoScalingGroupName $asAutoScalingGroupParams.AutoScalingGroupName
    $asAutoScalingGroup

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    $ecsCapacityProviderParams = @{ 
        'Name'                                                  = $("EC2ContainerService-{0}-EcsInstanceCp-{1}" -f $serviceFamily, [DateTimeOffset]::Now.ToUnixTimeSeconds());
        'AutoScalingGroupProvider_AutoScalingGroupArn'          = $asAutoScalingGroup.AutoScalingGroupARN;
        'AutoScalingGroupProvider_ManagedTerminationProtection' = "ENABLED";
        'ManagedScaling_MaximumScalingStepSize'                 = 1;
        'ManagedScaling_MinimumScalingStepSize'                 = 1;
        'ManagedScaling_Status'                                 = "DISABLED";
        'ManagedScaling_TargetCapacity'                         = 2;
        'Tag'                                                   = $nameTag,$serviceTag,$managementTag,$environmentTag;
    }
    $ecsCapacityProvider = New-ECSCapacityProvider @ecsCapacityProviderParams
    $ecsCapacityProvider

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    do{
        Write-Output "`t Checking ECS Capacity Provider status..."
        $ecsCapacityProvider = Get-ECSCapacityProvider -CapacityProvider $ecsCapacityProvider.CapacityProviderArn
        $ecsCapacityProvider
        Start-Sleep -Seconds 5
    } while($ecsCapacityProvider.Status -ne 'ACTIVE')
    Write-Output "`t ECS Capacity Provider verified."

    Write-Output "`t Creating ECS cluster..."
    $clusterStrategyItem = New-Object -TypeName Amazon.ECS.Model.CapacityProviderStrategyItem
    $clusterStrategyItem.Base = 0
    $clusterStrategyItem.CapacityProvider = $ecsCapacityProvider.Name
    $clusterStrategyItem.Weight = 1

    $clusterSetting = New-Object -TypeName Amazon.ECS.Model.ClusterSetting
    $clusterSetting.Name = "containerInsights"
    $clusterSetting.Value = "enabled"
    $ecs = New-ECSCluster -ClusterName $serviceFamily -Tag $nameTag,$serviceTag,$managementTag,$environmentTag -Setting $clusterSetting -CapacityProvider $ecsCapacityProvider.Name -DefaultCapacityProviderStrategy $clusterStrategyItem
    $ecs
    $ecs = Get-ECSClusterDetail -Cluster $ecs.ClusterArn

    Write-Output "`t Verifying ECS Capacity Provider Created..."
    do{
        Write-Output "`t Checking ECS Cluster has propagated..."
        $ecs = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn
        $ecs
        Start-Sleep -Seconds 5
    } while($ecs.Clusters[0].Status -ne 'ACTIVE')

    do{
        Write-Output "`t Checking ECS Cluster status..."
        $ecs = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn
        $ecs
        Start-Sleep -Seconds 5
    } while($ecs.Clusters[0].Status -ne 'ACTIVE')
    Write-Output "`t ECS cluster is active."
}

if($containerRepository) {
    # Creating the container repository
    Write-Output ""
    Write-Output "`t Begin creation and configuration of elastic container repository."
    
    Write-Output "`t Creating elastic container repository..."
    $containerName = ("{0}/{1}" -f $environment,$serviceFamily)
    $ecr = New-ECRRepository -RepositoryName $containerName -Tag $nameTag,$serviceTag,$managementTag,$environmentTag
    $ecr

    do{
        Write-Output "`t Checking ECR state..."
        $ecrExists = $false

        try {
            $ecr = Get-ECRRepository -RepositoryName $containerName
            if($ecr -ne $null) {
                $ecrExists = $true
            }
        } catch {
            Write-Output "`t ECR was not found, checking again..."
        }
        
        Start-Sleep -Seconds 5
    } while($ecrExists -ne $true)

    Write-Output "`t ECR created, tagged and active."
    Write-Output ""
}

Write-Output ""
Write-Output "`t Service environment created successfully."

# Begin validation
Write-Output "`t Validating Environment..."
$validationPassed = $false

$vpcValidated = $false
$vpcTest = Get-EC2Vpc -VpcId $vpc.VpcId
if($vpcTest.State -eq "available") {
    Write-Output ("`t`t VPC {0} validated" -f $vpc.VpcId)
    $vpcValidated = $true
}

$subnetsValidated = @()
foreach($subnet in $subnets) {
    $subnetTest = Get-EC2Subnet -SubnetId $subnet.SubnetId

    $subnetsValidated += $false
    if($subnetTest.State -eq "available") {
        Write-Output ("`t`t subnet {0} validated" -f $subnet.CidrBlock)
        $subnetsValidated[$subnetsValidated.Count-1] = $true
    }
}

$igwValidated = $false
$igwTest = Get-EC2InternetGateway -InternetGatewayId $igw.InternetGatewayId
if($igwTest.Attachments[0].State -eq "available") {
    Write-Output ("`t`t IGW {0} validated" -f $igw.InternetGatewayId)
    $igwValidated = $true
}

$sgValidated = $false
$sgTest = Get-EC2SecurityGroup -GroupId $sg
if($sgTest.VpcId -eq $vpc.VpcId) {
    Write-Output ("`t`t SG {0} validated" -f $sg)
    $sgValidated = $true
}

if($containerCluster) {
    $ecsValidated = $false
    $ec2KeyValidated = $false

    try {
        $ecsTest = Get-ECSClusterDetail -Cluster $ecs.Clusters[0].ClusterArn
        if($ecsTest -ne $null) {
            if($ecsTest.Clusters[0].Status -eq "ACTIVE") {
                $ecsValidated = $true
            }
            
            Write-Output ("`t`t ECS {0} validated" -f $ecsTest.Clusters[0].ClusterArn)
            $ecsValidated = $true
        }
    } catch {
        #
    }

    $ec2KeyValidated = $false
    if ((Test-Path("{0}-ec2Key.fingerprint" -f $serviceFamily)) -and (Test-Path("{0}-ec2Key.pem" -f $serviceFamily))) {
        Write-Output ("`t`t EC2 Key {0} validated" -f $serviceFamily)
        $ec2KeyValidated = $true
    }
} else {
    $ecsValidated = $true
    $ec2KeyValidated = $true
}

if($loadBalancer) {
    $elbValidated = $false
    $elbTest = Get-ELB2LoadBalancer -LoadBalancerArn $elb.LoadBalancerArn
    if($elbTest.State[0].Code -eq "active") {
        Write-Output ("`t`t ELB {0} validated" -f $elb.LoadBalancerName)
        $elbValidated = $true
    }
} else {
    $elbValidated = $true
}

if($containerRepository) {
    $ecrValidated = $false

    try {
        $ecrTest = Get-ECRRepository -RepositoryName $ecr.RepositoryName
        if($ecrTest -ne $null) {
            Write-Output ("`t`t ECR {0} validated" -f $ecr.RepositoryName)
            $ecrValidated = $true
        }
    } catch {
        #
    }
} else {
    $ecrValidated = $true
}

if($vpcValidated -and (($subnetsValidated | Unique).Count -eq 1 -and $subnetsValidated[0] -eq $true) -and $igwValidated -and $sgValidated -and $ec2KeyValidated -and $ecsValidated -and $elbValidated -and $ecrValidated) {
    $validationPassed = $true
}

$validationPassed
if($validationPassed) {
    Write-Output "`t Environment successfully validated"
} else {
    Write-Output "`t Validation failed, review logs."
}

Stop-Transcript

return $validationPassed