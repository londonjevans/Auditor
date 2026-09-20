// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Synthetic, abstract, local-only compiler input-closure control.
import {Dependency} from "./Dependency.sol";

abstract contract MissingImport is Dependency {}
