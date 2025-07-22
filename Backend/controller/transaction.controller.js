import Transaction from '../models/transaction.model.js';
import User from '../models/user.model.js';
import { contract, web3 } from '../blockchain.js';
import cleanBigInt from '../utils/cleanBigInt.js';
import { evaluateContext } from '../utils/contextEvaluator.js';
import { updateContextProfile } from '../utils/updateContextProfile.js';
import { sendSuspiciousTransactionAlert, sendTransactionVerificationEmail } from '../nodemailer/emails.js';
import { generateVerificationCode } from '../utils/generateVerificationCode.js';
import { detectFraud } from '../utils/detectFraud.js';

// Helper function to update user balances
const updateBalances = async (senderId, recipientId, amount) => {
  try {
    // Update sender balance (deduct amount)
    await User.findByIdAndUpdate(senderId, {
      $inc: { balance: -amount }
    });

    // Update recipient balance (add amount)
    await User.findByIdAndUpdate(recipientId, {
      $inc: { balance: amount }
    });

    return true;
  } catch (error) {
    console.error('Error updating balances:', error);
    return false;
  }
};

// Helper function to check if user has sufficient balance
const checkSufficientBalance = async (userId, amount) => {
  try {
    const user = await User.findById(userId);
    return user && user.balance >= amount;
  } catch (error) {
    console.error('Error checking balance:', error);
    return false;
  }
};

// Get all transactions
export const getUserTransactions = async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.userId })
      .populate('recipientId', 'name accountNumber ifscCode')
      .sort({ date: -1 });
    res.status(200).json(transactions);
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).json({ error: 'Server Error' });
  }
};

// Get incoming transactions (where user is the recipient)
export const getIncomingTransactions = async (req, res) => {
  try {
    const transactions = await Transaction.find({ recipientId: req.userId })
      .populate('userId', 'name accountNumber ifscCode')
      .sort({ date: -1 });
    res.status(200).json(transactions);
  } catch (err) {
    console.error('Error fetching incoming transactions:', err);
    res.status(500).json({ error: 'Server Error' });
  }
};

// Get transaction statistics for user
export const getTransactionStats = async (req, res) => {
  try {
    const userId = req.userId;
    
    // Get outgoing transactions
    const outgoingTransactions = await Transaction.find({ userId });
    const outgoingTotal = outgoingTransactions.reduce((sum, tx) => sum + tx.amount, 0);
    const outgoingCount = outgoingTransactions.length;
    
    // Get incoming transactions
    const incomingTransactions = await Transaction.find({ recipientId: userId });
    const incomingTotal = incomingTransactions.reduce((sum, tx) => sum + tx.amount, 0);
    const incomingCount = incomingTransactions.length;
    
    // Get recent transactions (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const recentOutgoing = await Transaction.find({
      userId,
      date: { $gte: thirtyDaysAgo }
    });
    const recentIncoming = await Transaction.find({
      recipientId: userId,
      date: { $gte: thirtyDaysAgo }
    });
    
    const stats = {
      outgoing: {
        total: outgoingTotal,
        count: outgoingCount,
        recentCount: recentOutgoing.length,
        recentTotal: recentOutgoing.reduce((sum, tx) => sum + tx.amount, 0)
      },
      incoming: {
        total: incomingTotal,
        count: incomingCount,
        recentCount: recentIncoming.length,
        recentTotal: recentIncoming.reduce((sum, tx) => sum + tx.amount, 0)
      },
      netFlow: incomingTotal - outgoingTotal
    };
    
    res.status(200).json(stats);
  } catch (err) {
    console.error('Error fetching transaction stats:', err);
    res.status(500).json({ error: 'Server Error' });
  }
};

// Get user balance
export const getUserBalance = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('balance name accountNumber');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.status(200).json({
      success: true,
      balance: user.balance,
      name: user.name,
      accountNumber: user.accountNumber
    });
  } catch (err) {
    console.error('Error fetching user balance:', err);
    res.status(500).json({ error: 'Server Error' });
  }
};

// Create transaction with blockchain (fallback to MongoDB if contract misconfigured)
export const createTransaction = async (req, res) => {
  try {
    const { amount, recipientAccountNumber, purpose, note, context, useBlockchain } = req.body;

    // 1. Ensure contract is configured
    // Validate required fields
    if (!amount || !recipientAccountNumber || !purpose) {
      return res.status(400).json({ error: 'Amount, recipient account number, and purpose are required' });
    }

    // Find recipient user by account number
    const recipientUser = await User.findOne({ accountNumber: recipientAccountNumber });
    if (!recipientUser) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    // Check if sender has sufficient balance
    const hasSufficientBalance = await checkSufficientBalance(req.userId, amount);
    if (!hasSufficientBalance) {
      return res.status(400).json({ error: 'Insufficient balance for this transaction' });
    }

    // Prevent self-transaction
    if (recipientUser._id.toString() === req.userId) {
      return res.status(400).json({ error: 'Cannot send money to yourself' });
    }

    // 2. Context-based security check
    if (context) {
      try {
        // Get user profile for context evaluation
        const user = await User.findById(req.userId);
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }

        // Evaluate context and calculate risk score
        const risk = evaluateContext(context, user);

        // Risk-based transaction logic
        if (risk >= 10) {
                  // Block transaction and send warning email for high risk
        await sendSuspiciousTransactionAlert(
          user.email,
          user.name,
          context,
          risk,
          { amount, recipient: recipientUser.name, accountNumber: recipientAccountNumber, purpose }
        );
          return res.status(403).json({
            success: false,
            message: "Suspicious activity detected, transaction blocked for your security. Check your email for details.",
            riskScore: risk
          });
        } else if (risk >= 5 && amount > 10000) {
          // Check if user already has a pending verification
          if (user.transactionVerificationToken && user.transactionVerificationExpiresAt > Date.now()) {
            return res.status(200).json({
              success: false,
              message: "Verification already in progress. Please check your email for the verification code.",
              requireVerification: true,
              riskScore: risk
            });
          }
          
          // Require additional verifm risk
          const verificationCode = generateVerificationCode();
          
          // Store pending transaction and verification token
          user.transactionVerificationToken = verificationCode;
          user.transactionVerificationExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
          user.pendingTransaction = {
            amount,
            recipient: recipientUser.name,
            accountNumber: recipientAccountNumber,
            ifsc: recipientUser.ifscCode,
            purpose,
            note,
            context,
            useBlockchain: useBlockchain || false
          };
          await user.save();

          // Send verification email
          await sendTransactionVerificationEmail(
            user.email,
            user.name,
            verificationCode,
            context,
            { amount, recipient: recipientUser.name, accountNumber: recipientAccountNumber, purpose }
          );

          return res.status(200).json({
            success: false,
            message: "Additional verification required due to unusual activity. Check your email for the verification code.",
            requireVerification: true,
            riskScore: risk
          });
        }

        // Update user's context profile with this transaction attempt
        // await updateContextProfile(user, context, risk);
      } catch (error) {
        console.error("Error evaluating context:", error);
        // Continue with transaction even if context evaluation fails
      }
    }

    // Check if contract is properly configured
    if (!contract?.methods?.createTransaction || typeof contract.methods.createTransaction !== 'function') {
      console.error("Blockchain contract not configured! ABI or address may be wrong.");
      // Fallback: Just save to MongoDB with "No Blockchain" status
      
      // Update balances
      const balanceUpdated = await updateBalances(req.userId, recipientUser._id, amount);
      if (!balanceUpdated) {
        return res.status(500).json({ error: 'Failed to update balances' });
      }

      const newTransaction = new Transaction({
        userId: req.userId,
        amount,
        recipient: recipientUser.name,
        recipientId: recipientUser._id,
        accountNumber: recipientAccountNumber,
        ifsc: recipientUser.ifscCode,
        purpose,
        note,
        date: new Date(),
        status: "Success (No Blockchain)",
        txHash: null, // No blockchain tx hash
        validated: false,
        chainStatus: "OffChain",
        blockchainLog: null,
      });
      await newTransaction.save();
      return res.status(201).json(cleanBigInt(newTransaction.toObject ? newTransaction.toObject() : newTransaction));
    }

    // 3. Get sender address (in production, use user's wallet)
    const accounts = await web3.eth.getAccounts();
    const senderAddress = accounts[0];

    // 4. Create transaction on blockchain
    let tx;
    try {
      tx = await contract.methods
        .createTransaction(recipientUser.name, amount)
        .send({ from: senderAddress, gas: 300000 });
    } catch (err) {
      return res.status(500).json({ error: "Blockchain transaction creation failed: " + err.message });
    }

    // 5. Get transaction hash (adjust if your contract emits differently)
    const txHash = tx.events && tx.events.TransactionCreated
      ? tx.events.TransactionCreated.returnValues.txHash
      : tx.transactionHash;

    // 6. Validate transaction on blockchain (if your contract supports it)
    let validate;
    try {
      validate = await contract.methods
        .validateTransaction(txHash)
        .send({ from: senderAddress, gas: 100000 });
    } catch (err) {
      return res.status(500).json({ error: "Blockchain transaction validation failed: " + err.message });
    }

    // 7. Fraud detection using AI
    const isFraud = await detectFraud(amount, recipientUser._id, req.userId);
    if (isFraud) {
      return res.status(400).json({ error: "Fraud detected" });
    }

    // 8. Update balances
    const balanceUpdated = await updateBalances(req.userId, recipientUser._id, amount);
    if (!balanceUpdated) {
      return res.status(500).json({ error: 'Failed to update balances' });
    }

    // 9. Save transaction to DB with blockchain status
    const newTransaction = new Transaction({
      userId: req.userId,
      amount,
      recipient: recipientUser.name,
      recipientId: recipientUser._id,
      accountNumber: recipientAccountNumber,
      ifsc: recipientUser.ifscCode,
      purpose,
      note,
      date: new Date(),
      status: "Success (with Blockchain)",
      txHash,
      validated: true,
      chainStatus: "OnChain",
      blockchainLog: validate, // Save validation log for audit
    });

    await newTransaction.save();
    res.status(201).json(cleanBigInt(newTransaction.toObject ? newTransaction.toObject() : newTransaction));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Transaction Error: " + err.message });
  }
};

// Verify transaction with verification code
export const verifyTransaction = async (req, res) => {
  try {
    const { verificationCode } = req.body;
    if (!verificationCode) {
      return res.status(400).json({ error: 'Verification code is required' });
    }

    // Find user with matching verification token
    const user = await User.findOne({
      _id: req.userId,
      transactionVerificationToken: verificationCode,
      transactionVerificationExpiresAt: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    // Get pending transaction details
    const pendingTransaction = user.pendingTransaction;
    if (!pendingTransaction) {
      return res.status(400).json({ error: 'No pending transaction found' });
    }

    // Clear verification tokens and remove pending transaction
    await User.findByIdAndUpdate(req.userId, {
      $unset: {
        transactionVerificationToken: 1,
        transactionVerificationExpiresAt: 1,
        pendingTransaction: 1
      }
    });

    // Process the transaction
    const { amount, recipient, accountNumber, ifsc, purpose, note, useBlockchain } = pendingTransaction;
    
    // Find recipient user by account number (in case it was stored differently)
    const recipientUser = await User.findOne({ accountNumber });
    if (!recipientUser) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    // Check if contract is properly configured
    if (!contract?.methods?.createTransaction || typeof contract.methods.createTransaction !== 'function') {
      console.error("Blockchain contract not configured! ABI or address may be wrong.");
      
      // Update balances
      const balanceUpdated = await updateBalances(req.userId, recipientUser._id, amount);
      if (!balanceUpdated) {
        return res.status(500).json({ error: 'Failed to update balances' });
      }
      
      // Fallback: Just save to MongoDB with "No Blockchain" status
      const newTransaction = new Transaction({
        userId: req.userId,
        amount,
        recipient: recipientUser.name,
        recipientId: recipientUser._id,
        accountNumber,
        ifsc: recipientUser.ifscCode,
        purpose,
        note,
        date: new Date(),
        status: "Success (No Blockchain) - Verified",
        txHash: null,
        validated: false,
        chainStatus: "OffChain",
        blockchainLog: null,
      });
      await newTransaction.save();
      return res.status(201).json(cleanBigInt(newTransaction.toObject ? newTransaction.toObject() : newTransaction));
    }

    // Process blockchain transaction if requested
    if (useBlockchain) {
      const accounts = await web3.eth.getAccounts();
      const senderAddress = accounts[0];

      let tx;
      try {
        tx = await contract.methods
          .createTransaction(recipientUser.name, amount)
          .send({ from: senderAddress, gas: 300000 });
      } catch (err) {
        return res.status(500).json({ error: "Blockchain transaction creation failed: " + err.message });
      }

      const txHash = tx.events && tx.events.TransactionCreated
        ? tx.events.TransactionCreated.returnValues.txHash
        : tx.transactionHash;

      let validate;
      try {
        validate = await contract.methods
          .validateTransaction(txHash)
          .send({ from: senderAddress, gas: 100000 });
      } catch (err) {
        return res.status(500).json({ error: "Blockchain transaction validation failed: " + err.message });
      }

      // Update balances
      const balanceUpdated = await updateBalances(req.userId, recipientUser._id, amount);
      if (!balanceUpdated) {
        return res.status(500).json({ error: 'Failed to update balances' });
      }

      const newTransaction = new Transaction({
        userId: req.userId,
        amount,
        recipient: recipientUser.name,
        recipientId: recipientUser._id,
        accountNumber,
        ifsc: recipientUser.ifscCode,
        purpose,
        note,
        date: new Date(),
        status: "Success (with Blockchain) - Verified",
        txHash,
        validated: true,
        chainStatus: "OnChain",
        blockchainLog: validate,
      });

      await newTransaction.save();
      return res.status(201).json(cleanBigInt(newTransaction.toObject ? newTransaction.toObject() : newTransaction));
    } else {
      // Update balances
      const balanceUpdated = await updateBalances(req.userId, recipientUser._id, amount);
      if (!balanceUpdated) {
        return res.status(500).json({ error: 'Failed to update balances' });
      }
      
      // Save to MongoDB only
      const newTransaction = new Transaction({
        userId: req.userId,
        amount,
        recipient: recipientUser.name,
        recipientId: recipientUser._id,
        accountNumber,
        ifsc: recipientUser.ifscCode,
        purpose,
        note,
        date: new Date(),
        status: "Success - Verified",
      });

      await newTransaction.save();
      return res.status(201).json(cleanBigInt(newTransaction.toObject ? newTransaction.toObject() : newTransaction));
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Transaction Verification Error: " + err.message });
  }
};
