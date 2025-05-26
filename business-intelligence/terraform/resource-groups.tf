resource "aws_resourcegroups_group" "web" {
  name        = "emis-business-intelligence"
  description = "All IBI servers"

  resource_query {
    query = <<JSON
{
  "ResourceTypeFilters": [
    "AWS::EC2::Instance"
  ],
  "TagFilters": [
    {
      "Key": "rg_service",
      "Values": ["aws-ibi"]
    }
  ]
}
JSON
  }
}