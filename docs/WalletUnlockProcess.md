# Wallet Unlock Process with max limit on failed attempts

## Overview

The Wallet Unlock feature provides a secure mechanism to access a user's encrypted wallet using their PIN. This process includes sophisticated security measures such as temporary and permanent locking mechanisms to prevent brute force attacks, along with PIN-based decryption of wallet key. The unlock flow is triggered when a user needs to access their wallet after session expiry or initial login.

## Key Features

- PIN-based wallet unlocking
- Progressive security with temporary and permanent locking
- Configurable failed attempt limits and lock cycles
- Automatic lock expiry for temporary locks
- Session-based wallet key storage
- Last attempt warning before permanent lockout

## Sequence Diagram

The sequence diagram below illustrates the complete unlock process, including validation, PIN verification, and lock management steps.

```mermaid
sequenceDiagram
actor Client
participant WalletsController
participant WalletService
participant WalletUnlockService
participant WalletLockManager
participant WalletStatusService
participant WalletUtil
participant WalletRepository

    Client->>WalletsController: POST /wallets/{walletId}/unlock
    activate WalletsController
    
    WalletsController->>WalletService: unlockWallet(walletId, pin, userId)
    activate WalletService
    
    WalletService->>WalletService: validateUserId & validateWalletPin
    WalletService->>WalletRepository: findByUserIdAndId(userId, walletId)
    activate WalletRepository
    WalletRepository-->>WalletService: Wallet object
    deactivate WalletRepository
    
    WalletService->>WalletUnlockService: handleUnlock(wallet, pin)
    activate WalletUnlockService
    
    WalletUnlockService->>WalletLockManager: resetTemporaryLockIfExpired(wallet)
    activate WalletLockManager
    Note over WalletLockManager: Checks if Wallet is temporarily locked before and that lock has expired, then it resets<br/> the failedAttemptCount and retryBlockedUntil to their defaults, and set the wallet status to lock_expired
    WalletLockManager-->>WalletUnlockService: Returns updated Wallet
    deactivate WalletLockManager
    
    WalletUnlockService->>WalletStatusService: validateWalletStatus(wallet)
    activate WalletStatusService
    Note over WalletStatusService: Checks if wallet is<br/>permanently_locked or<br/>temporarily_locked
    alt if yes 
        WalletStatusService-->>WalletUnlockService: Throws exception for permanently_locked or temporarily_locked
        WalletUnlockService-->>WalletService: Throws the received exception
        deactivate WalletStatusService
    else otherwise
        WalletUnlockService->>WalletUtil: decryptWalletKey(walletKey, pin)
        alt Successful PIN Decryption
            WalletUtil-->>WalletUnlockService: Returns the decryptedWalletKey
            activate WalletUtil
            deactivate WalletUtil
            
            WalletUnlockService->>WalletLockManager: resetLockState(wallet)
            activate WalletLockManager
            Note over WalletLockManager: Reset all lock counters,<br/>retryBlockedUntil and status to default values
            WalletLockManager-->>WalletUnlockService: Returns updated Wallet
            deactivate WalletLockManager
            
            WalletUnlockService->>WalletRepository: save(wallet)
            activate WalletRepository
            deactivate WalletRepository
            WalletUnlockService-->>WalletService: Returns the decryptedWalletKey
        else Invalid PIN
            WalletUnlockService->>WalletLockManager: enforceLockCyclePolicy(wallet)
            activate WalletLockManager
            
            Note over WalletLockManager:1. Increments failedAttemptCount<br/>2. If failedAttemptCount = maxFailedAttemptsAllowedPerCycle then increments currentCycleCount and sets Wallet status to <br/> - permanently_locked if currentCycleCount > maxLockCyclesAllowed<br/> - temporarily_locked if currentCycleCount <= maxLockCyclesAllowed<br/>3.If failedAttemptCount = maxFailedAttemptsAllowedPerCycle -1 & currentCycleCount = maxLockCyclesAllowed then sets wallet status to<br/> - last_attempt_before_lockout as only one attempt is left before permanent lockout
            
            WalletLockManager-->>WalletUnlockService: Returns updated Wallet
            deactivate WalletLockManager
          
            WalletUnlockService->>WalletStatusService: validateLastAttemptBeforeLockout(wallet)
            activate WalletStatusService
            Note over WalletStatusService: Check if Wallet status is set to last_attempt_before_lockout
            alt if yes
                WalletStatusService-->>WalletUnlockService: Throws exception as only one attempt left before permanent lockout to unlock the Wallet
                deactivate WalletStatusService
                WalletUnlockService-->>WalletRepository: save(wallet)
                activate WalletRepository
                deactivate WalletRepository
                WalletUnlockService-->>WalletService: Throws exception for last_attempt_before_lockout
            else otherwise
                WalletUnlockService->>WalletLockManager: resetTemporaryLockIfExpired(wallet)
                activate WalletLockManager
                Note over WalletLockManager: Checks if Wallet is temporarily locked before and that lock has expired, then it resets<br/> the failedAttemptCount and retryBlockedUntil to their defaults, and set the wallet status to lock_expired
                WalletLockManager-->>WalletUnlockService: Returns updated Wallet
                deactivate WalletLockManager
                
                WalletUnlockService->>WalletStatusService: validateWalletStatus(wallet)
                activate WalletStatusService
                Note over WalletStatusService: Checks if wallet is<br/>permanently_locked or<br/>temporarily_locked
                alt if yes 
                    WalletStatusService-->>WalletUnlockService: Throws exception for permanently_locked or temporarily_locked
                    deactivate WalletStatusService
                    WalletUnlockService-->>WalletRepository: save(wallet)
                    activate WalletRepository
                    deactivate WalletRepository
                    WalletUnlockService-->>WalletService: Throws exception for permanently_locked or temporarily_locked
                else otherwise
                    WalletUnlockService-->>WalletRepository: save(wallet)
                    activate WalletRepository
                    deactivate WalletRepository
                    WalletUnlockService-->>WalletService: Throws exception for invalid pin
                    deactivate WalletUnlockService
                end
            end 
        end
    end
    
    WalletService-->>WalletsController: Returns WalletResponseDto on successful Wallet unlock or throws Exception
    deactivate WalletService
    
    alt Success Response
        WalletsController->>WalletsController: Stores the wallet_key & wallet_id into Http session
        WalletsController-->>Client: Returns 200 OK status with WalletResponseDto
    else Error Response
        WalletsController-->>Client: Returns Error status with ErrorDTO
    end
    deactivate WalletsController
```
## Configuration

Configurable properties that govern the entire Passcode flow within the Wallet unlock process are defined in the
`application-local.properties` file for the local setup, and in the `mimoto-default.properties` file for the environment setup.

#### Passcode Control Properties
- `wallet.passcode.retryBlockedUntil`: Duration for which the Wallet remains in temporary lock state (in milliseconds)
- `wallet.passcode.maxFailedAttemptsAllowedPerCycle`: Maximum number of failed attempts allowed before triggering a temporary lock cycle
- `wallet.passcode.maxLockCyclesAllowed`: Maximum lock cycles allowed before permanent lockout

```properties
# Duration (in milliseconds) for which the wallet remains locked after exceeding failed attempts in a cycle
wallet.passcode.retryBlockedUntil=3600000
# Maximum number of failed passcode attempts allowed in a single cycle (defaults to 1 if <=0)
wallet.passcode.maxFailedAttemptsAllowedPerCycle=5
# Maximum number of lock cycles allowed before the wallet is permanently locked (defaults to 1 if <=0)
wallet.passcode.maxLockCyclesAllowed=3
```