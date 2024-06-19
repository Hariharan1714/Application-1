// server.js

const express = require('express');
const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const Razorpay = require('razorpay');
const jwt = require('jsonwebtoken'); // Import JWT

const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = 'your_secret_key'; // Replace with your own secret key

const sequelize = new Sequelize('nodejs', 'root', '1718', {
  host: 'localhost',
  dialect: 'mysql'
});

const razorpay = new Razorpay({
  key_id: 'rzp_test_Sv1ndMmezEYbe5',
  key_secret: 'XnjNy66vXo4k1sYMetDzgXYe'
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const User = require('./models/User')(sequelize, DataTypes);
const Expense = require('./models/Expense')(sequelize, DataTypes);

User.hasMany(Expense);
Expense.belongsTo(User);

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).send('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
    await User.create({ name, email, password: hashedPassword });

    res.redirect('/login?signupSuccess=true');
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).send('Error creating user');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log('User not found:', email);
      return res.status(404).send('User not found');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match for', email, ':', passwordMatch); // Add this line

    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' }); // Generate JWT
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).send('Error logging in');
  }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).send('Token required');

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

app.post('/add-expense', authenticateToken, async (req, res) => {
  const { amount, description, category } = req.body;
  const userId = req.user.userId;
  try {
    const user = await User.findByPk(userId);
    if (!user) {
      console.error('User not found for ID:', userId);
      return res.status(404).send('User not found');
    }

    const newExpense = await Expense.create({ amount, description, category, UserId: userId });
    await user.addExpense(newExpense);
    res.status(201).send('Expense added successfully!');
  } catch (error) {
    console.error('Error adding expense:', error.message);
    res.status(500).send('Error adding expense');
  }
});

app.get('/expenses', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const expenses = await Expense.findAll({ where: { UserId: userId } });
    res.json(expenses);
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).send('Error fetching expenses');
  }
});

app.delete('/delete-expense/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;
  try {
    const expense = await Expense.findByPk(id);
    if (!expense) {
      return res.status(404).send('Expense not found');
    }

    if (expense.UserId !== userId) {
      return res.status(403).send('You do not have permission to delete this expense');
    }

    await expense.destroy();
    res.status(200).send('Expense deleted successfully');
  } catch (error) {
    console.error('Error deleting expense:', error);
    res.status(500).send('Error deleting expense');
  }
});

app.post('/create-order', async (req, res) => {
  console.log('Attempting to create Razorpay order'); // Add this line for explicit logging
  try {
    const options = {
      amount: 2500, // amount in paise (25 INR)
      currency: 'INR',
      receipt: 'receipt_order_74394',
      payment_capture: 0 // 1 for automatic capture, 0 for manual capture
    };

    const order = await razorpay.orders.create(options);
    res.json({ orderId: order.id });
  } catch (error) {
    console.error('Error creating Razorpay order:', error); // Log error to terminal
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/payment-response', authenticateToken, async (req, res) => {
    const { paymentId, orderId, status } = req.body;

    try {
        if (status === 'success') {
            // Retrieve the user ID from the token
            const userId = req.user.userId;

            // Find the user in the database
            const user = await User.findByPk(userId);

            if (user) {
                // Update the isPremium column
                user.isPremium = true;
                await user.save();

                res.json({ message: 'Payment successful and user updated to premium' });
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        } else {
            // Handle payment failure
            res.status(400).json({ error: 'Payment failed' });
        }
    } catch (error) {
        console.error('Error processing payment response:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
