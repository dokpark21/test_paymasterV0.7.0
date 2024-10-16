# Makefile

# Target: build_test
build_test:
	# Remove existing lib folder and cached submodules
	rm -rf lib
	git rm -r --cached lib/account-abstraction-v6 || true
	rm -rf .git/modules/lib/account-abstraction-v6
	rm -rf lib/account-abstraction-v6

	# Add account-abstraction-v6 submodule and checkout to specific commit
	git submodule add https://github.com/eth-infinitism/account-abstraction.git lib/account-abstraction-v6
	cd lib/account-abstraction-v6 && git checkout fa61290d37d079e928d92d53a122efcc63822214

	# Remove account-abstraction-v7 submodule and cached entries
	git rm -r --cached lib/account-abstraction-v7 || true
	rm -rf .git/modules/lib/account-abstraction-v7
	rm -rf lib/account-abstraction-v7

	# Add account-abstraction-v7 submodule and checkout to specific commit
	git submodule add https://github.com/eth-infinitism/account-abstraction.git lib/account-abstraction-v7
	cd lib/account-abstraction-v7 && git checkout 7af70c8993a6f42973f520ae0752386a5032abe7

	# Install dependencies without committing
	forge install uniswap/v3-core --no-commit
	forge install uniswap/v3-periphery --no-commit
	forge install foundry-rs/forge-std --no-commit
	forge install OpenZeppelin/openzeppelin-contracts --no-commit

# Optional: Clean target to remove lib and submodule data
clean:
	rm -rf lib
	git submodule deinit -f --all
	rm -rf .git/modules/lib