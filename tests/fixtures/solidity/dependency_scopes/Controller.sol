// Synthetic source-only lexical binding controls. No funds or deployment.
pragma solidity ^0.8.20;
import {IReserve} from "./IReserve.sol";

contract Controller {
    IReserve private reserve;
    IReserve private cursor;

    constructor() { revert("Synthetic source-only fixture: deployment prohibited"); }

    function stateValue() external view returns (uint256) {
        return reserve.value();
    }

    function parameterValue(IReserve reserve) external view returns (uint256) {
        return reserve.value();
    }

    function localValue(IReserve input) external view returns (uint256) {
        IReserve reserve = input;
        return reserve.value();
    }

    function nestedValue(IReserve input) external view returns (uint256) {
        reserve.value();
        {
            IReserve reserve = input;
            reserve.value();
        }
        return reserve.value();
    }

    function loopValue(IReserve input, bool keepGoing) external view returns (uint256) {
        for (IReserve cursor = input; keepGoing; ) {
            cursor.value();
            break;
        }
        return cursor.value();
    }

    function castValue(address input) external view returns (uint256) {
        return IReserve(input).value();
    }

    function unrelated(uint256 IReserve) external pure returns (uint256) {
        return IReserve;
    }
}
