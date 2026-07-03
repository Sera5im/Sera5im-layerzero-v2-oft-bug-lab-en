// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableMinAmountOApp {
    address public owner;
    address public endpoint;

    mapping(address => uint256) public balances;

    address public lastRecipient;
    uint256 public lastAmountSentLD;
    uint256 public lastAmountReceivedLD;
    uint32 public lastDstEid;

    error NotOwner();
    error InsufficientBalance();
    error SlippageExceeded(uint256 amountReceivedLD, uint256 minAmountLD);

    constructor(address _endpoint) {
        owner = msg.sender;
        endpoint = _endpoint;
        balances[msg.sender] = 1_000_000 * 10**18;
    }

    function send(
        address from,
        address to,
        uint256 amountLD,
        uint256 minAmountLD,
        uint32 dstEid
    ) external returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        if (msg.sender != from && msg.sender != owner) revert NotOwner();

        (amountSentLD, amountReceivedLD) = _debit(from, amountLD, minAmountLD, dstEid);
        bytes memory message = _buildMessage(to, amountReceivedLD, dstEid);
        _lzReceive(message);

        lastAmountSentLD = amountSentLD;
        lastAmountReceivedLD = amountReceivedLD;
        lastDstEid = dstEid;
    }

    function _debit(
        address from,
        uint256 amountLD,
        uint256 minAmountLD,
        uint32 dstEid
    ) internal returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        (amountSentLD, amountReceivedLD) = _debitView(amountLD, minAmountLD, dstEid);

        if (balances[from] < amountSentLD) revert InsufficientBalance();
        balances[from] -= amountSentLD;
    }

    function _debitView(
        uint256 amountLD,
        uint256 minAmountLD,
        uint32 /* dstEid */
    ) internal pure returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        // VULNERABILITY:
        // minAmount check is applied to the raw input amount before normalization
        if (amountLD < minAmountLD) {
            revert SlippageExceeded(amountLD, minAmountLD);
        }

        amountSentLD = _removeDust(amountLD);
        amountReceivedLD = amountSentLD;
    }

    function _removeDust(uint256 amountLD) internal pure returns (uint256) {
        return (amountLD / 100) * 100;
    }

    function _buildMessage(
        address to,
        uint256 amountReceivedLD,
        uint32 dstEid
    ) internal pure returns (bytes memory) {
        return abi.encode(to, amountReceivedLD, dstEid);
    }

    function _lzReceive(bytes memory message) internal {
        (address to, uint256 amountReceivedLD, ) = abi.decode(message, (address, uint256, uint32));
        _credit(to, amountReceivedLD);
    }

    function _credit(address to, uint256 amountReceivedLD) internal {
        balances[to] += amountReceivedLD;
        lastRecipient = to;
    }
}
