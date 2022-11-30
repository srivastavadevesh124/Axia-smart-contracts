// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "@openzeppelin/contracts/math/SafeMath.sol";
import "./libs/IBEP20.sol";
import "./libs/SafeBEP20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./AXCToken.sol";

// import "@nomiclabs/buidler/console.sol";
interface IMigratorChef {
    function migrate(IBEP20 token) external returns (IBEP20);
}

// MasterChef is the master of AXC. He can make AXC and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once AXC is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterChef is Ownable , ReentrancyGuard {
    using SafeMath for uint256;
    using SafeBEP20 for IBEP20;

    // Info of each user.
    struct UserInfo {
        uint256 amount;         // How many LP tokens the user has provided.
        uint256 rewardDebt;     // Reward debt. See explanation below.
        //
        // We do some fancy math here. Basically, any point in time, the amount of AXCs
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accAXCPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accAXCPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IBEP20 lpToken;           // Address of LP token contract.
        uint256 allocPoint;       // How many allocation points assigned to this pool. AXCs to distribute per block.
        uint256 lastRewardBlock;  // Last block number that AXCs distribution occurs.
        uint256 accAXCPerShare;   // Accumulated AXCs per share, times 1e12. See below.
        uint16 depositFeeBP;      // Deposit fee in basis points
    }

    // The AXC TOKEN!
    AXCToken public AXC;
    // AXC tokens created per block.
    uint256 public AXCPerBlock;
    // Bonus muliplier for early AXC makers.
    uint256 public constant BONUS_MULTIPLIER = 1;
    // Deposit Fee address
    address public feeAddress;
    // total AXC staked
    uint256 public totalAXCStaked;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping (uint256 => mapping (address => UserInfo)) public userInfo;
    // active pools
    mapping(address => bool) public activeLpTokens;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when AXC mining starts.
    uint256 public startBlock;
     // The migrator contract. It has a lot of power. Can only be set through governance (owner).
    IMigratorChef public migrator;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event PoolMigrated(uint256 indexed pid);

    constructor(
        AXCToken _AXC,
        address _feeAddress,
        uint256 _AXCPerBlock,
        uint256 _startBlock
    ) public {
        AXC = _AXC;
        feeAddress = _feeAddress;
        AXCPerBlock = _AXCPerBlock;
        startBlock = _startBlock;
    }

    modifier validatePoolByPid(uint256 _pid) {
        require(_pid < poolInfo.length, "Pool does not exist");
        _;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    function add(uint256 _allocPoint, IBEP20 _lpToken, uint16 _depositFeeBP, bool _withUpdate) public onlyOwner nonReentrant {
        require(_depositFeeBP <= 10000, "add: invalid deposit fee basis points");
        
        require(
            activeLpTokens[address(_lpToken)] == false,
            "Reward Token already added"
        );

        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accAXCPerShare: 0,
            depositFeeBP: _depositFeeBP
        }));
        
        activeLpTokens[address(_lpToken)] = true;
    }

    // Update the given pool's AXC allocation point and deposit fee. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, uint16 _depositFeeBP, bool _withUpdate) public validatePoolByPid(_pid) nonReentrant onlyOwner {
        require(_depositFeeBP <= 10000, "set: invalid deposit fee basis points");
        massUpdatePools();
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
    }

    // Migrate lp token to another lp contract. Can be called by anyone. We trust that migrator contract is good.
    function migrate(uint256 _pid)
        external
        validatePoolByPid(_pid)
        nonReentrant
    {
        require(address(migrator) != address(0), "migrate: no migrator");
        PoolInfo storage pool = poolInfo[_pid];
        IBEP20 lpToken = pool.lpToken;
        uint256 bal = lpToken.balanceOf(address(this));
        lpToken.approve(address(migrator), bal);
        IBEP20 newLpToken = migrator.migrate(lpToken);
        require(bal == newLpToken.balanceOf(address(this)), "migrate: bad");
        pool.lpToken = newLpToken;

        emit PoolMigrated(_pid);
    }
     
    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        return _to.sub(_from).mul(BONUS_MULTIPLIER);
    }

    // View function to see pending AXCs on frontend.
    function pendingAXC(uint256 _pid, address _user) external view validatePoolByPid(_pid) returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accAXCPerShare = pool.accAXCPerShare;
        uint256 lpSupply;
        if(address(pool.lpToken) == address(AXC)){
         lpSupply = totalAXCStaked;
        }else{
         lpSupply = pool.lpToken.balanceOf(address(this));
        }    
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 AXCReward = multiplier.mul(AXCPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accAXCPerShare = accAXCPerShare.add(AXCReward.mul(1e12).div(lpSupply));
        }
        return user.amount.mul(accAXCPerShare).div(1e12).sub(user.rewardDebt);
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) validatePoolByPid(_pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply;
        if(address(pool.lpToken) == address(AXC)){
         lpSupply = totalAXCStaked;
        }else{
         lpSupply = pool.lpToken.balanceOf(address(this));
        }
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 AXCReward = multiplier.mul(AXCPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        pool.accAXCPerShare = pool.accAXCPerShare.add(AXCReward.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for AXC allocation.
    function deposit(uint256 _pid, uint256 _amount) validatePoolByPid(_pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accAXCPerShare).div(1e12).sub(user.rewardDebt);
            if(pending > 0) {
                safeAXCTransfer(msg.sender, pending);
            }
        }
        if(_amount > 0) {
            pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
            if(pool.depositFeeBP > 0){
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                user.amount = user.amount.add(_amount).sub(depositFee);
                if(address(pool.lpToken) == address(AXC)){
                  totalAXCStaked = totalAXCStaked.add(_amount.sub(depositFee)); 
               }
            }else{
                user.amount = user.amount.add(_amount);
                if(address(pool.lpToken) == address(AXC)){
               totalAXCStaked = totalAXCStaked.add(_amount); 
            }
            }
            
        }
        user.rewardDebt = user.amount.mul(pool.accAXCPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef.
    function withdraw(uint256 _pid, uint256 _amount) validatePoolByPid(_pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        uint256 pending = user.amount.mul(pool.accAXCPerShare).div(1e12).sub(user.rewardDebt);
        if(pending > 0) {
            safeAXCTransfer(msg.sender, pending);
        }
        if(_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
            if(address(pool.lpToken) == address(AXC)){
               totalAXCStaked = totalAXCStaked.sub(_amount); 
            }
        }
        user.rewardDebt = user.amount.mul(pool.accAXCPerShare).div(1e12);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public validatePoolByPid(_pid) nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        if(address(pool.lpToken) == address(AXC)){
            totalAXCStaked = totalAXCStaked.sub(amount); 
        }
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    // Safe AXC transfer function, just in case if rounding error causes pool to not have enough AXCs.
    function safeAXCTransfer(address _to, uint256 _amount) internal {
        uint256 AXCBal = AXC.balanceOf(address(this));
        if (_amount > AXCBal) {
            AXC.transfer(_to, AXCBal);
        } else {
            AXC.transfer(_to, _amount);
        }
    }

    function setFeeAddress(address _feeAddress) public{
        require(msg.sender == feeAddress, "setFeeAddress: FORBIDDEN");
        feeAddress = _feeAddress;
    }

    //Pancake has to add hidden dummy pools inorder to alter the emission, here we make it simple and transparent to all.
    function updateEmissionRate(uint256 _AXCPerBlock) public onlyOwner {
        massUpdatePools();
        AXCPerBlock = _AXCPerBlock;
    }
}