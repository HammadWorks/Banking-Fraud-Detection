import axios from 'axios';
import User from "../models/user.model.js";

const typeMap = {
  CASH_IN: 0,
  CASH_OUT: 1,
  DEBIT: 2,
  PAYMENT: 3,
  TRANSFER: 4
};


export const detectFraud = async (amount, recipientId, userId) => {
  try {
    const user = await User.findById(userId);
    const recipient = await User.findById(recipientId);

    const oldbalanceOrig = Number(user.balance);
    const oldbalanceDest = Number(recipient.balance);
    const newbalanceOrig = oldbalanceOrig - Number(amount);
    const newbalanceDest = oldbalanceDest + Number(amount);

    const payload = {
      type: typeMap['TRANSFER'],
      amount: Number(amount),
      oldbalanceOrig,
      newbalanceOrig,
      oldbalanceDest,
      newbalanceDest
    };

    const response = await axios.post('http://localhost:5001/predict-fraud', payload);
    const prediction = response.data?.prediction;
    const probability = response.data?.probability;

    console.log("Fraud prediction:", prediction);
    console.log("Probability:", probability);

    return prediction === "FRAUD";
  } catch (err) {
    console.error("Error while detecting fraud:", err.message);
    return false; // fallback to safe side
  }
};