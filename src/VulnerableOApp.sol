// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableOApp {
    address public owner;
    address public endpoint;

    mapping(uint32 => bytes32) public peers;

    mapping(address => uint256) public balances;

    address public lastRecipient;
    uint256 public lastAmountSentLD;
    uint256 public lastAmountReceivedLD;
    uint32 public lastDstEid;

    error NotOwner();
    error NotEndpoint();
    error NoPeer(uint32 eid);
    error InsufficientBalance();
    error SlippageExceeded(uint256 amountReceivedLD, uint256 minAmountLD);

    constructor(address _endpoint) {
        owner = msg.sender;
        endpoint = _endpoint;
        balances[msg.sender] = 1_000_000 * 10**18;
    }

    function setPeer(uint32 eid, bytes32 peer) external {
        // VULNERABILITY:
        // peer configuration is mutable by arbitrary users
        peers[eid] = peer;
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
        amountSentLD = _removeDust(amountLD);

        // VULNERABILITY:
        // destination-side amount is no longer tied to normalized source-side accounting
        amountReceivedLD = amountLD;

        if (amountReceivedLD < minAmountLD) {
            revert SlippageExceeded(amountReceivedLD, minAmountLD);
        }
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

    function lzReceive(uint32 srcEid, bytes32 sender, bytes calldata message) external {
        if (msg.sender != endpoint) revert NotEndpoint();

        // VULNERABILITY:
        // no validation that `sender` matches the trusted peer configured for `srcEid`
        srcEid;
        sender;
        _lzReceive(message);
    }

    function _lzReceive(bytes memory message) internal {
        (address to, uint256 amountReceivedLD, ) = abi.decode(message, (address, uint256, uint32));
        _credit(to, amountReceivedLD);
    }

    function _credit(address to, uint256 amountReceivedLD) internal {
        // VULNERABILITY:
        // zero-address recipient is silently replaced by caller context
        if (to == address(0)) {
            to = msg.sender;
        }

        balances[to] += amountReceivedLD;
        lastRecipient = to;
    }

    function _getPeerOrRevert(uint32 eid) internal view returns (bytes32) {
        bytes32 peer = peers[eid];
        if (peer == bytes32(0)) revert NoPeer(eid);
        return peer;
    }
}
