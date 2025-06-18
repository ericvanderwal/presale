// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract PresaleFundraiser is Ownable, ReentrancyGuard {
    struct ContributionRecord {
        address token;
        uint256 amount;
        uint256 timestamp;
        bytes32 hashedReferral;
        bytes32 hashedEmail;
        address signer;
    }

    // Tracks contributions by user
    mapping(address => ContributionRecord[]) public contributions;

    // Tracks total contribution per token (e.g. USDC, USDT)
    mapping(address => uint256) public totalPerToken;

    // Tracks all contributors who used a given referral code
    mapping(bytes32 => address[]) public referralToContributors;

    // Tracks all unique contributors
    address[] public contributorList;

    event Contributed(
        address indexed contributor,
        address indexed token,
        uint256 amount,
        bytes32 hashedReferral,
        bytes32 hashedEmail,
        uint256 indexed contributionIndex
    );

    event Withdrawn(address indexed token, address indexed to, uint256 amount);

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Submit a presale contribution
     * @param token ERC20 token address
     * @param amount Token amount to transfer
     * @param hashedReferral keccak256 of referral code
     * @param hashedEmail keccak256 of user email
     */
    function contribute(
        address token,
        uint256 amount,
        bytes32 hashedReferral,
        bytes32 hashedEmail
    ) external nonReentrant {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");

        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // Store contribution record
        contributions[msg.sender].push(ContributionRecord({
            token: token,
            amount: amount,
            timestamp: block.timestamp,
            hashedReferral: hashedReferral,
            hashedEmail: hashedEmail,
            signer: msg.sender
        }));

        // Update token and referral totals
        totalPerToken[token] += amount;
        referralToContributors[hashedReferral].push(msg.sender);

        // Track unique contributors
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
     * @notice Admin: Withdraw tokens to treasury or multisig
     */
    function withdraw(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        require(token != address(0), "Invalid token");
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Amount must be greater than 0");

        IERC20(token).transfer(to, amount);
        emit Withdrawn(token, to, amount);
    }

    /**
     * @notice Fallback to accept ETH donations (not tracked)
     */
    receive() external payable {}
    fallback() external payable {}

    // ----------------------------
    // View Functions
    // ----------------------------

    function getContributorCountByAddress(address user) external view returns (uint256) {
        return contributions[user].length;
    }

    function getContributionByIndex(address user, uint256 index)
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

    function getAllContributions(address user)
        external
        view
        returns (ContributionRecord[] memory)
    {
        return contributions[user];
    }

    function getTotalForTokens(address[] calldata tokens)
        external
        view
        returns (uint256[] memory totals)
    {
        totals = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            totals[i] = totalPerToken[tokens[i]];
        }
    }

    function getReferralContributors(bytes32 referralHash)
        external
        view
        returns (address[] memory)
    {
        return referralToContributors[referralHash];
    }

    function getTotalUniqueContributors() external view returns (uint256) {
        return contributorList.length;
    }

    /**
     * @notice Returns all contributions from a user between two timestamps
     * @param user The user to check
     * @param startTimestamp Minimum timestamp (inclusive)
     * @param endTimestamp Maximum timestamp (inclusive)
     */
    function getContributionsInTimeRange(
        address user,
        uint256 startTimestamp,
        uint256 endTimestamp
    ) external view returns (ContributionRecord[] memory results) {
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
}