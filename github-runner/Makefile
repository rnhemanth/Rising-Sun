bootstrap-dev:
	@echo "- Bootstrap dev environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap dev eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform
	@echo "✓ Done"

bootstrap-stg:
	@echo "- Bootstrap stg environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap stg eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform
	@echo "✓ Done"

bootstrap-prd:
	@echo "- Bootstrap prd environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap prd eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform
	@echo "✓ Done"

destroy-role-dev:
	@echo "- Destroying role in dev environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap dev eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform destroy
	@echo "✓ Done"

destroy-role-stg:
	@echo "- Destroying role in stg environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap stg eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform destroy
	@echo "✓ Done"

destroy-role-prd:
	@echo "- Destroying role in prd environment..."
	chmod +x ./eweblogs/bootstrap/setup
	./eweblogs/bootstrap/setup bootstrap prd eweblogs england eu-west-2 aws-infra-deploy-eweblogs eweblogs-platform destroy
	@echo "✓ Done"