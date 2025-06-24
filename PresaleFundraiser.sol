// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title PresaleFundraiser
 * @author Uprising
 * @notice A presale contribution contract for ERC20 and ETH tokens, with referral tracking and minimum stablecoin enforcement.
 */
contract PresaleFundraiser is Ownable, Pausable, ReentrancyGuard {
    struct ContributionRecord {
        address token;
        uint256 amount;
        uint256 timestamp;
        bytes32 hashedReferral;
        bytes32 hashedEmail;
        address signer;
    }

    /// @notice Maps each contributor to their contribution records
    mapping(address => ContributionRecord[]) public contributions;

    /// @notice Tracks total contribution per ERC20 token
    mapping(address => uint256) public totalPerToken;

    /// @notice Maps a referral code to all addresses that used it
    mapping(bytes32 => address[]) public referralToContributors;

    /// @notice List of all unique contributors
    address[] public contributorList;

    /// @notice Allowed ERC20 tokens
    mapping(address => bool) public allowedERC20s;

    /// @notice Flags tokens that are stablecoins and should enforce a minimum contribution
    mapping(address => bool) public isStablecoin;

    /// @notice Minimum required amount for stablecoin contributions
    uint256 public minimumStablecoinAmount;

    /// @notice List of all tokens that have been configured (ever set as allowed or disallowed)
    address[] public configuredTokens;

    /// @notice Maps token address to its index in the configuredTokens array
    mapping(address => uint256) public tokenIndex;

    /// @notice Tracks if a token has been configured before
    mapping(address => bool) public isConfigured;

    /// @notice Emitted when a user contributes
    event Contributed(
        address indexed contributor,
        address indexed token,
        uint256 amount,
        bytes32 hashedReferral,
        bytes32 hashedEmail,
        uint256 indexed contributionIndex
    );

    /// @notice Emitted on admin token withdrawals
    event Withdrawn(address indexed token, address indexed to, uint256 amount);

    /// @notice Emitted when ETH is sent to the contract
    event EthDonated(address indexed donor, uint256 amount);

    /// @notice Emitted when a token is allowed or disallowed
    event ERC20AllowedUpdated(address indexed token, bool allowed);

    /// @notice Emitted when a token is marked as a stablecoin or unmarked
    event StablecoinFlagUpdated(address indexed token, bool isStable);

    /// @notice Emitted when the minimum stablecoin amount is updated
    event MinimumStablecoinAmountUpdated(uint256 newAmount);

    /// @notice Emitted when contract is paused
    event ContractPaused();

    /// @notice Emitted when contract is unpaused
    event ContractUnpaused();

    /**
     * @notice Constructor initializes the Ownable context.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @notice Contribute ERC20 tokens to the presale
     * @dev Only allowed tokens accepted. Stablecoins must meet minimum amount.
     * @param token ERC20 token address
     * @param amount Amount to contribute
     * @param hashedReferral keccak256 of referral string (can be zero for no referral)
     * @param hashedEmail keccak256 of user's email (can be zero for no email)
     */
    function contribute(
        address token,
        uint256 amount,
        bytes32 hashedReferral,
        bytes32 hashedEmail
    ) external whenNotPaused nonReentrant {
        require(token != address(0), "Invalid token address");
        require(allowedERC20s[token], "Token not allowed");
        require(amount > 0, "Amount must be greater than 0");

        if (isStablecoin[token]) {
            require(
                amount >= minimumStablecoinAmount,
                "Amount below stablecoin minimum"
            );
        }

        // Transfer tokens first - if this fails, no state changes occur
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // Update state after successful transfer
        contributions[msg.sender].push(
            ContributionRecord({
                token: token,
                amount: amount,
                timestamp: block.timestamp,
                hashedReferral: hashedReferral,
                hashedEmail: hashedEmail,
                signer: msg.sender
            })
        );

        totalPerToken[token] += amount;

        // Only track referral if it's not zero (valid referral provided)
        if (hashedReferral != bytes32(0)) {
            // Check if user already exists in this referral array
            bool alreadyExists = false;
            for (
                uint i = 0;
                i < referralToContributors[hashedReferral].length;
                i++
            ) {
                if (referralToContributors[hashedReferral][i] == msg.sender) {
                    alreadyExists = true;
                    break;
                }
            }
            if (!alreadyExists) {
                referralToContributors[hashedReferral].push(msg.sender);
            }
        }

        if (contributions[msg.sender].length == 1) {
            contributorList.push(msg.sender);
        }

        emit Contributed(
            msg.sender,
            token,
            amount,
            hashedReferral,
            hashedEmail,
            contributions[msg.sender].length - 1
        );
    }

    /**
     * @notice Accepts ETH donations (not tracked per user)
     * @dev This function allows the contract to receive ETH without any specific tracking
     * @dev Emits EthDonated event with donor address and amount
     */
    receive() external payable {
        emit EthDonated(msg.sender, msg.value);
    }

    // ----------------------------
    // Admin Configuration
    // ----------------------------

    /**
     * @notice Add or update an allowed ERC20 token and optionally mark it as a stablecoin
     * @dev Only callable by contract owner
     * @param token ERC20 token address to configure
     * @param allowed True to allow the token for contributions, false to disallow
     * @param stable True if token should be treated as a stablecoin (enforces minimum)
     * @dev Emits ERC20AllowedUpdated and StablecoinFlagUpdated events
     */
    function setAllowedERC20(
        address token,
        bool allowed,
        bool stable
    ) external onlyOwner {
        require(token != address(0), "Zero address");
        allowedERC20s[token] = allowed;
        isStablecoin[token] = stable;

        // Add to configured tokens list if not already there
        if (!isConfigured[token]) {
            configuredTokens.push(token);
            tokenIndex[token] = configuredTokens.length - 1;
            isConfigured[token] = true;
        }

        emit ERC20AllowedUpdated(token, allowed);
        emit StablecoinFlagUpdated(token, stable);
    }

    /**
     * @notice Remove a token from the allowlist and clear stablecoin status
     * @dev Only callable by contract owner
     * @param token ERC20 token address to remove from allowed tokens
     * @dev Emits ERC20AllowedUpdated and StablecoinFlagUpdated events with false values
     */
    function removeAllowedERC20(address token) external onlyOwner {
        require(token != address(0), "Zero address");
        require(isConfigured[token], "Token not configured");

        allowedERC20s[token] = false;
        isStablecoin[token] = false;

        emit ERC20AllowedUpdated(token, false);
        emit StablecoinFlagUpdated(token, false);
    }

    /**
     * @notice Mark a token as a stablecoin (enforces min contribution) or remove flag
     * @dev Only callable by contract owner
     * @param token ERC20 token address to configure
     * @param stable True if token is a stablecoin, false to remove stablecoin flag
     * @dev Emits StablecoinFlagUpdated event
     */
    function setStablecoinFlag(address token, bool stable) external onlyOwner {
        require(token != address(0), "Zero address");
        isStablecoin[token] = stable;
        emit StablecoinFlagUpdated(token, stable);
    }

    /**
     * @notice Set the minimum contribution amount required for stablecoins
     * @dev Only callable by contract owner
     * @param newAmount New minimum amount in smallest units (e.g., 500e6 for USDC)
     * @dev Emits MinimumStablecoinAmountUpdated event
     */
    function setMinimumStablecoinAmount(uint256 newAmount) external onlyOwner {
        require(newAmount > 0, "Minimum must be greater than 0");
        minimumStablecoinAmount = newAmount;
        emit MinimumStablecoinAmountUpdated(newAmount);
    }

    /**
     * @notice Pause the contract (disables contributions)
     * @dev Only callable by contract owner
     * @dev Prevents new contributions while paused
     * @dev Emits ContractPaused event
     */
    function pause() external onlyOwner {
        _pause();
        emit ContractPaused();
    }

    /**
     * @notice Unpause the contract (enables contributions)
     * @dev Only callable by contract owner
     * @dev Re-enables contributions after pause
     * @dev Emits ContractUnpaused event
     */
    function unpause() external onlyOwner {
        _unpause();
        emit ContractUnpaused();
    }

    /**
     * @notice Withdraw ERC20 tokens from contract
     * @dev Only callable by contract owner
     * @dev Uses nonReentrant modifier to prevent reentrancy attacks
     * @param token ERC20 token to withdraw
     * @param to Recipient address for the tokens
     * @param amount Amount of tokens to send
     * @dev Emits Withdrawn event
     */
    function withdraw(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner nonReentrant {
        require(token != address(0), "Invalid token");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Amount must be greater than 0");

        IERC20(token).transfer(to, amount);
        emit Withdrawn(token, to, amount);
    }

    // ----------------------------
    // Read Functions
    // ----------------------------

    /**
     * @notice Get how many contributions a user has made
     * @param user Wallet address of contributor
     * @return count Number of contributions made by the user
     */
    function getContributorCountByAddress(
        address user
    ) external view returns (uint256 count) {
        return contributions[user].length;
    }

    /**
     * @notice Get a specific contribution by user and index
     * @param user Contributor address
     * @param index Index into their contribution array (0-based)
     * @return token Contributed token address
     * @return amount Contributed amount
     * @return timestamp Timestamp of contribution
     * @return hashedReferral Referral hash used for this contribution
     * @return hashedEmail Email hash used for this contribution
     * @return signer Original signer (msg.sender) of the contribution
     */
    function getContributionByIndex(
        address user,
        uint256 index
    )
        external
        view
        returns (
            address token,
            uint256 amount,
            uint256 timestamp,
            bytes32 hashedReferral,
            bytes32 hashedEmail,
            address signer
        )
    {
        ContributionRecord storage c = contributions[user][index];
        return (
            c.token,
            c.amount,
            c.timestamp,
            c.hashedReferral,
            c.hashedEmail,
            c.signer
        );
    }

    /**
     * @notice Get all contributions made by a user
     * @param user Wallet address of the contributor
     * @return records Array of all ContributionRecord structs for the user
     */
    function getAllContributions(
        address user
    ) external view returns (ContributionRecord[] memory records) {
        return contributions[user];
    }

    /**
     * @notice Get total amounts contributed for a list of tokens
     * @param tokens Array of ERC20 token addresses to query
     * @return totals Array of total amounts contributed for each token (matching input order)
     */
    function getTotalForTokens(
        address[] calldata tokens
    ) external view returns (uint256[] memory totals) {
        totals = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            totals[i] = totalPerToken[tokens[i]];
        }
    }

    /**
     * @notice Get list of all addresses that used a referral code
     * @param referralHash keccak256 hash of the referral string
     * @return addresses Array of unique contributor addresses that used this referral
     */
    function getReferralContributors(
        bytes32 referralHash
    ) external view returns (address[] memory addresses) {
        return referralToContributors[referralHash];
    }

    /**
     * @notice Get total number of unique contributors
     * @return count Total number of unique addresses that have contributed
     */
    function getTotalUniqueContributors()
        external
        view
        returns (uint256 count)
    {
        return contributorList.length;
    }

    /**
     * @notice Get contributions by a user within a timestamp range
     * @param user Address of the contributor
     * @param startTimestamp Start of range (inclusive) in Unix timestamp
     * @param endTimestamp End of range (inclusive) in Unix timestamp
     * @return results Array of ContributionRecord structs within the specified time range
     * @dev Returns empty array if no contributions found in range
     */
    function getContributionsInTimeRange(
        address user,
        uint256 startTimestamp,
        uint256 endTimestamp
    ) external view returns (ContributionRecord[] memory results) {
        require(startTimestamp <= endTimestamp, "Invalid time range");
        ContributionRecord[] storage userRecords = contributions[user];
        uint256 count = 0;

        for (uint256 i = 0; i < userRecords.length; i++) {
            if (
                userRecords[i].timestamp >= startTimestamp &&
                userRecords[i].timestamp <= endTimestamp
            ) {
                count++;
            }
        }

        results = new ContributionRecord[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < userRecords.length; i++) {
            if (
                userRecords[i].timestamp >= startTimestamp &&
                userRecords[i].timestamp <= endTimestamp
            ) {
                results[index] = userRecords[i];
                index++;
            }
        }
    }

    /**
     * @notice Get all configured ERC20 tokens and their configurations
     * @return tokens Array of all configured token addresses
     * @return allowed Array of boolean values indicating if tokens are allowed
     * @return stable Array of boolean values indicating if tokens are stablecoins
     */
    function getAllowedTokens()
        external
        view
        returns (
            address[] memory tokens,
            bool[] memory allowed,
            bool[] memory stable
        )
    {
        uint256 count = configuredTokens.length;
        tokens = new address[](count);
        allowed = new bool[](count);
        stable = new bool[](count);

        for (uint256 i = 0; i < count; i++) {
            address token = configuredTokens[i];
            tokens[i] = token;
            allowed[i] = allowedERC20s[token];
            stable[i] = isStablecoin[token];
        }
    }

    /**
     * @notice Check if a specific token is allowed and its configuration
     * @param token ERC20 token address to check
     * @return isAllowed True if token is allowed for contributions
     * @return isStable True if token is marked as a stablecoin
     * @return configured True if token has been configured before
     */
    function getTokenConfig(
        address token
    ) external view returns (bool isAllowed, bool isStable, bool configured) {
        return (allowedERC20s[token], isStablecoin[token], isConfigured[token]);
    }

    /**
     * @notice Get the total number of configured tokens
     * @return count Number of tokens that have been configured
     */
    function getConfiguredTokenCount() external view returns (uint256 count) {
        return configuredTokens.length;
    }

    /**
     * @notice Get a specific configured token by index
     * @param index Index in the configured tokens array
     * @return token Address of the configured token
     * @return allowed True if token is currently allowed
     * @return stable True if token is marked as stablecoin
     */
    function getConfiguredTokenByIndex(
        uint256 index
    ) external view returns (address token, bool allowed, bool stable) {
        require(index < configuredTokens.length, "Index out of bounds");
        token = configuredTokens[index];
        allowed = allowedERC20s[token];
        stable = isStablecoin[token];
    }
}
