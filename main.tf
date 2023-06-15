provider "aws" {
  region = "us-east-1"
}

data "aws_eks_cluster" "clustinfo" {
  name = "cluster-za"
}
# output "identity-oidc-issuer" {
#   value = trimprefix(data.aws_eks_cluster.clustinfo.identity[0].oidc[0].issuer,"https://oidc.eks.us-east-1.amazonaws.com/id/")
# }

# output "endpoint" {
#   value = data.aws_eks_cluster.clustinfo.endpoint
# }

# output "certbody"{
#   value = data.aws_eks_cluster.clustinfo.certificate_authority[0].data
# }

locals {
  oidcval = trimprefix(data.aws_eks_cluster.clustinfo.identity[0].oidc[0].issuer,"https://oidc.eks.us-east-1.amazonaws.com/id/")
  awsacc = "657907747545"
  region = "us-east-1"

  sapath = abspath("albSA.yaml")
#   installalb = templatefile(abspath("v2_4_4_full.tftpl"), { clustername = "cluster-za"})
  serviceacc = <<EOF
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    labels:
      app.kubernetes.io/component: controller
      app.kubernetes.io/name: aws-load-balancer-controller
    name: aws-load-balancer-controller
    namespace: kube-system
    annotations:
      eks.amazonaws.com/role-arn: ${aws_iam_role.eks-alb-controller.arn}
  EOF
}

# resource "aws_iam_role" "eks-ebs-csi-diver" {
#   name = data.aws_eks_cluster.clustinfo.id
#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Principal": {
#         "Federated": "arn:aws:iam::${local.awsacc}:oidc-provider/oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}"
#       },
#       "Action": "sts:AssumeRoleWithWebIdentity",
#       "Condition": {
#         "StringEquals": {
#           "oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}:aud": "sts.amazonaws.com",
#           "oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
#         }
#       }
#     }
#   ]
# }
# EOF
# }

resource "aws_iam_policy" "policy" {
  name        = "eks-cluster-elb-controller-setup"
 # path        = "/"
  description = "cluster ALB setup policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL",
                "shield:GetSubscriptionState",
                "shield:DescribeProtection",
                "shield:CreateProtection",
                "shield:DeleteProtection"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "StringEquals": {
                    "ec2:CreateAction": "CreateSecurityGroup"
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:DeleteRule"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ],
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeleteTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:SetWebAcl",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:ModifyRule"
            ],
            "Resource": "*"
        }
    ]
  })
}


resource "aws_iam_role" "eks-alb-controller" {
  name = "eks-elb-add-on-with-policy-attched-iamrole"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
 "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${local.awsacc}:oidc-provider/oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}:aud": "sts.amazonaws.com",
                    "oidc.eks.${local.region}.amazonaws.com/id/${local.oidcval}:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
                }
            }
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "eks-ebs-policy-attachment" {
    role = "${aws_iam_role.eks-alb-controller.name}"
    policy_arn = "${aws_iam_policy.policy.arn}"
}

resource "local_file" "safile" {
  content  = "${local.serviceacc}"
  filename = "albSA.yaml"
}

resource "null_resource" "clustert" {
  provisioner "local-exec" {
    command = "kubectl apply -f ${local.sapath}"
  }
  depends_on = [local_file.safile]
}

resource "null_resource" "albcert" {
  provisioner "local-exec" {
    command = "kubectl apply -f cert-manager.yaml"
  }
}

resource "null_resource" "albinstall" {
  provisioner "local-exec" {
    command = "kubectl apply -f v2_4_4_full.yaml"
  }
}


# resource "aws_iam_role_policy_attachment" "eks-ebs-policy-attachment" {
#     role = "${aws_iam_role.eks-ebs-csi-diver.name}"
#     policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
# }

# resource "aws_iam_role_policy_attachment" "eks-ebs-policy_custom-attachment" {
#     role = "${aws_iam_role.eks-ebs-csi-diver.name}"
#     policy_arn = "arn:aws:iam::657907747545:policy/AmazonEKS_EBS_CSI_Driver_Policy"
# }

# provider "kubernetes" {
#   host                   = data.aws_eks_cluster.clustinfo.endpoint
#   cluster_ca_certificate = base64decode(data.aws_eks_cluster.clustinfo.certificate_authority[0].data)

#   exec {
#     api_version = "client.authentication.k8s.io/v1"
#     command     = "aws"
#     # This requires the awscli to be installed locally where Terraform is executed
#     args = ["eks", "get-token", "--cluster-name", data.aws_eks_cluster.clustinfo.id]
#   }
# }

# resource "kubernetes_annotations" "ebs_annotate" {
#   api_version = "v1"
#   kind        = "serviceaccount"
#   metadata {
#     name = "ebs-csi-controller-sa"
#     namespace = "kube-system"
#   }
#   annotations = {
#     "eks.amazonaws.com/role-arn" = "${aws_iam_role.eks-ebs-csi-diver.arn}"
#   }
# }

# resource "null_resource" "clustert" {
#   provisioner "local-exec" {
#     command = "kubectl.exe annotate serviceaccount ebs-csi-controller-sa -n kube-system --overwrite=true eks.amazonaws.com/role-arn=${aws_iam_role.eks-ebs-csi-diver.arn}"
#   }
# }
