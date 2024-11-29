const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const cron = require('node-cron');

// Initialize app
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
// app.use('/uploads', express.static('uploads'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// app.use(express.static('public'));  
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb+srv://expenza:expenza@expenza.oygju.mongodb.net/expenza', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('MongoDB connected successfully');
})
.catch(err => {
  console.error('MongoDB connection error:', err.message);
});

// User Schema
// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    profits: { type: Number, default: 0 },
    profitsPaused: { type: Boolean, default: false },
    notifications: [{ message: String, date: { type: Date, default: Date.now } }],
    currentPlan: { type: String, default: null },
    blocked: { type: Boolean, default: false },
    referralLink: { type: String }, // Add this field to store the referral link
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    referredUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    referralCount: { type: Number, default: 0 },
    approved: { type: Boolean, default: false } 
   
});


const User = mongoose.model('User', userSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: { type: Number, required: true },
    type: { type: String, enum: ['deposit', 'withdrawal'], required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    proof: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
});

const Transaction = mongoose.model('Transaction', transactionSchema);


// Plan Schema
const planSchema = new mongoose.Schema({
    name: { type: String, required: true },
    baseAmount: { type: Number, required: true }, // The base amount for the plan
    duration: { type: String, required: true }, // Duration of the plan (e.g., "1 month")
    description: { type: String, default: '' }, // Description of the plan
});

const Plan = mongoose.model('Plan', planSchema);


// Building Schema and Model
const buildingSchema = new mongoose.Schema({
    name: String,
    description: String,
    location: String,
    investmentPrice: Number,
    returnOnInvestment: Number,
    numberOfRooms: Number,
    numberOfBathrooms: Number,
    image: String,
});

const Building = mongoose.model('Building', buildingSchema);




// Middleware for verifying JWT tokens
const authenticate = (req, res, next) => {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1]; // Format: 'Bearer token_value'

    if (!token) {
        return res.status(401).json({ message: 'Token missing' });
    }

    // Verify the token
    jwt.verify(token, 'aHSCWvC3Ol', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' }); // Return 403 if token is not valid
        }

        req.user = user; // Attach decoded user information to request object
        next(); // Proceed to the next middleware or route handler
    });
};

// Middleware to verify if a user is approved
const ensureApproved = async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user || !user.approved) {
      return res.status(403).json({ message: 'User not approved' });
    }
    next();
  };

// // File upload configuration
// const storage = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, 'uploads/');
//     },
//     filename: (req, file, cb) => {
//         cb(null, Date.now() + path.extname(file.originalname));
//     },
// });


// Multer Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({ storage });

// Helper Functions
const emitNotification = (userId, message) => {
    io.to(userId.toString()).emit('notification', { message });
};


// Socket connection handling
io.on('connection', (socket) => {
    console.log('New client connected');

    // Handle user-specific socket room
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`User ${userId} joined the room.`);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});


// Function to schedule profit increments with a steady increase
// const scheduleProfitIncrement = (user, incrementConfig) => {
//     const { percentageRate, minimumIncrement, interval } = incrementConfig;

//     // Schedule a task to run every 24 hours
//     const task = cron.schedule(interval, async () => {
//         const percentageIncrement = user.profits * percentageRate; // Calculate percentage-based increment
//         const increment = Math.max(percentageIncrement, minimumIncrement); // Determine the final increment

//         // Apply the increment to the user's profits
//         user.profits += increment;
//         await user.save();

//         // Send notifications
//         emitNotification(
//             user._id,
//             `Your profits have been updated! Current profits: $${user.profits.toFixed(2)}`
//         );

//         // Emit updated profits to WebSocket
//         io.to(user._id.toString()).emit('profitUpdate', { profits: user.profits });
//     });

//     // Start the cron task 
//     task.start();
// };


const scheduleProfitIncrement = (user, incrementConfig) => {
    if (!incrementConfig) {
        console.error('Increment configuration is missing');
        return;
    }

    const { percentageRate, minimumIncrement, interval } = incrementConfig;

    // Schedule a task to run every 24 hours
    const task = cron.schedule(interval, async () => {
        const percentageIncrement = user.profits * percentageRate;
        const increment = Math.max(percentageIncrement, minimumIncrement);

        user.profits += increment;
        await user.save();

        emitNotification(
            user._id,
            `Your profits have been updated! Current profits: $${user.profits.toFixed(2)}`
        );

        io.to(user._id.toString()).emit('profitUpdate', { profits: user.profits });
    });

    task.start();
};


// Call this function for each user with configurable increments
User.find({}).then(users => {
    // Configuration for profit increment
    const incrementConfig = {
        percentageRate: 0.05, // 5% increment
        minimumIncrement: 10, // Minimum $10 increment
        interval: '0 0 * * *' // Every day at midnight
    };

    users.forEach(user => scheduleProfitIncrement(user, incrementConfig));
});

 
//User Registration
app.post('/api/users/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ email, password: hashedPassword, name });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});


// User Login
app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id }, 'aHSCWvC3Ol', { expiresIn: '1h' });
    res.json({ token });
});


// Get All Buildings
app.get('/api/buildings', async (req, res) => {
    try {
        const buildings = await Building.find();
        res.json(buildings);
    } catch (error) {
        console.error('Error fetching buildings:', error);
        res.status(500).json({ message: 'Error fetching buildings' });
    }
});


// Get a Single Building by ID
app.get('/api/buildings/:id', async (req, res) => {
    try {
        const building = await Building.findById(req.params.id);
        if (!building) {
            return res.status(404).json({ message: 'Building not found' });
        }
        res.json(building);
    } catch (error) {
        console.error('Error fetching building:', error);
        res.status(500).json({ message: 'Error fetching building' });
    }
});

// Create a New Building
app.post('/api/buildings', upload.single('image'), async (req, res) => {
    try {
        const {
            name,
            description,
            location,
            investmentPrice,
            returnOnInvestment,
            numberOfRooms,
            numberOfBathrooms,
        } = req.body;

        const building = new Building({
            name,
            description,
            location,
            investmentPrice,
            returnOnInvestment,
            numberOfRooms,
            numberOfBathrooms,
            image: req.file ? `/uploads/${req.file.filename}` : '',
        });

        await building.save();
        res.status(201).json({ message: 'Building created successfully', building });
    } catch (error) {
        console.error('Error creating building:', error);
        res.status(500).json({ message: 'Error creating building' });
    }
});

// Update a Building
app.put('/api/buildings/:id', upload.single('image'), async (req, res) => {
    try {
        const {
            name,
            description,
            location,
            investmentPrice,
            returnOnInvestment,
            numberOfRooms,
            numberOfBathrooms,
        } = req.body;

        const building = await Building.findById(req.params.id);
        if (!building) {
            return res.status(404).json({ message: 'Building not found' });
        }

        building.name = name || building.name;
        building.description = description || building.description;
        building.location = location || building.location;
        building.investmentPrice = investmentPrice || building.investmentPrice;
        building.returnOnInvestment = returnOnInvestment || building.returnOnInvestment;
        building.numberOfRooms = numberOfRooms || building.numberOfRooms;
        building.numberOfBathrooms = numberOfBathrooms || building.numberOfBathrooms;

        if (req.file) {
            building.image = `/uploads/${req.file.filename}`;
        }

        await building.save();
        res.json({ message: 'Building updated successfully', building });
    } catch (error) {
        console.error('Error updating building:', error);
        res.status(500).json({ message: 'Error updating building' });
    }
});

// Delete a Building
app.delete('/api/buildings/:id', async (req, res) => {
    try {
        const building = await Building.findById(req.params.id);
        if (!building) {
            return res.status(404).json({ message: 'Building not found' });
        }

        await building.deleteOne();
        res.json({ message: 'Building deleted successfully' });
    } catch (error) {
        console.error('Error deleting building:', error);
        res.status(500).json({ message: 'Error deleting building' });
    }
});

// Get user details, including profits
app.get('/api/users/me', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Respond with the required user details
        res.json({
            email: user.email,
            balance: user.balance,
            name: user.name,
            profits: user.profits
        });
    } catch (error) {
        // Handle server errors
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Deposit Transaction
app.post('/api/transactions/deposit', authenticate, upload.single('proofOfPayment'), async (req, res) => {
    const { amount } = req.body;

    if (!req.file) {
        return res.status(400).json({ message: 'Proof of payment is required.' });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ message: 'Invalid amount.' });
    }

    try {
        const transaction = new Transaction({
            userId: req.user.id,
            amount: parsedAmount,
            proof: req.file.filename,
            type: 'deposit',
        });
        await transaction.save();

        res.status(201).json(transaction);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// Approve Deposit
app.post('/api/admin/transactions/approve-deposit/:id', async (req, res) => {
    const transactionId = req.params.id;
    const transaction = await Transaction.findById(transactionId);

    if (transaction && transaction.type === 'deposit' && transaction.status === 'pending') {
        const user = await User.findById(transaction.userId);
        user.balance += transaction.amount;
        user.profits += transaction.amount * 0.05; // Initial 5% profit on approved deposit
        await user.save();

        user.notifications.push({
            message: `Your deposit of $${transaction.amount} has been approved. Your balance and profits have been updated!`,
        });
        await user.save();

        transaction.status = 'approved';
        await transaction.save();

        emitNotification(user._id, `Your deposit of $${transaction.amount} has been approved. Your balance and profits have been updated!`);
        scheduleProfitIncrement(user); // Start the task for the user

        return res.status(200).json(transaction);
    }
    return res.status(400).json({ message: 'Transaction not found or already processed' });
});

// Withdraw Transaction
app.post('/api/transactions/withdraw', authenticate, async (req, res) => {
    const { amount } = req.body;

    try {
        const user = await User.findById(req.user.id);
        if (user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        const transaction = new Transaction({
            userId: req.user.id,
            amount: -parseFloat(amount),
            type: 'withdrawal',
        });
        await transaction.save();

        user.balance -= parseFloat(amount);
        await user.save();

        emitNotification(user._id, `Your withdrawal of $${amount} has been processed. Your current balance: $${user.balance.toFixed(2)}`);

        res.status(201).json(transaction);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});


// Approve Withdrawal
app.post('/api/admin/transactions/approve-withdrawal/:id', async (req, res) => {
    const transactionId = req.params.id;
    const transaction = await Transaction.findById(transactionId).populate('userId');

    if (transaction && transaction.type === 'withdrawal' && transaction.status === 'pending') {
        const user = transaction.userId;

        // Check if user has sufficient balance
        if (user.balance < Math.abs(transaction.amount)) {
            return res.status(400).json({ message: 'Insufficient balance for this withdrawal.' });
        }

        // Deduct the withdrawal amount from the user's balance
        user.balance -= Math.abs(transaction.amount);
        await user.save();

        // Update transaction status to approved
        transaction.status = 'approved';
        await transaction.save();

        emitNotification(user._id, `Your withdrawal of $${Math.abs(transaction.amount)} has been approved. Your current balance: $${user.balance.toFixed(2)}`);

        return res.status(200).json(transaction);
    }

    return res.status(400).json({ message: 'Transaction not found or already processed' });
});


// Get User Withdrawal History
app.get('/api/transactions/withdrawal-history', authenticate, async (req, res) => {
    try {
        // Fetch withdrawals for the authenticated user
        const withdrawals = await Transaction.find({
            userId: req.user.id,
            type: 'withdrawal' // Only fetching withdrawal transactions
        }).sort({ createdAt: -1 }); // Sort by date, latest first

        // Check if withdrawals exist
        if (withdrawals.length === 0) {
            return res.status(404).json({ message: 'No withdrawal history found for this user.' });
        }

        // Return the withdrawal history
        res.json(withdrawals);
    } catch (error) {
        // Handle server errors
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Get User Deposit History
app.get('/api/transactions/deposit-history', authenticate, async (req, res) => {
    try {
        // Fetch deposits for the authenticated user
        const deposits = await Transaction.find({
            userId: req.user.id,
            type: 'deposit' // Only fetching deposit transactions
        }).sort({ createdAt: -1 }); // Sort by date, latest first

        // Check if deposits exist
        if (deposits.length === 0) {
            return res.status(404).json({ message: 'No deposit history found for this user.' });
        }

        // Return the deposit history
        res.json(deposits);
    } catch (error) {
        // Handle server errors
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Get User Transaction History
app.get('/api/transactions/history', authenticate, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Get a single user's referral link and referral-related properties
app.get('/api/users/referral-info', authenticate, async (req, res) => {
    console.log('Referral Info endpoint hit');  // Log for confirmation

    const userId = req.user.id; // Assuming `req.user` is populated by the authenticate middleware

    try {
        const user = await User.findById(userId).populate('referredUsers', 'name email');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const referralInfo = {
            referralLink: user.referralLink,      // The user's referral link
            referredBy: user.referredBy,          // The user who referred them
            referredUsers: user.referredUsers,    // Array of users referred by this user
            referralCount: user.referralCount      // Count of how many users this user has referred
        };

        res.json(referralInfo);
    } catch (error) {
        console.error('Error fetching referral info:', error);  // Log the error for troubleshooting
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});



// Get User Transactions
app.get('/api/admin/transactions/:userId', async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.params.userId });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});





// Admin Deposit Route
app.post('/api/admin/deposit/:userId', async (req, res) => {
    const { amount } = req.body;
    const userId = req.params.userId; // Get userId from the URL parameter

    // Validate amount
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ message: 'Invalid amount.' });
    }

    try {
        // Create a new deposit transaction
        const transaction = new Transaction({
            userId: userId,
            amount: parsedAmount,
            type: 'deposit',
            status: 'approved', // Automatically approve for admin deposits
        });

        // Save the transaction
        await transaction.save();

        // Update user's balance
        const user = await User.findById(userId);
        user.balance += parsedAmount; // Update the user's balance
        await user.save();

        // Emit notification to the user about the deposit
        emitNotification(userId, `Your account has been credited with $${parsedAmount}.`); 
        
        res.status(201).json(transaction);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});



// Fetch all proofs of payment
app.get('/api/admin/proofs-of-payment', async (req, res) => {
    try {
        const proofs = await Transaction.find({ type: 'deposit', proof: { $ne: null } }).populate('userId', 'name email');
        
        if (!proofs.length) {
            return res.status(404).json({ message: 'No proofs of payment found.' });
        }

        res.json(proofs);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});



app.get('/api/admin/dashboard', async (req, res) => {
    try {
        const pendingDeposits = await Transaction.find({ type: 'deposit', status: 'pending' }).populate('userId');
        const pendingWithdrawals = await Transaction.find({ type: 'withdrawal', status: 'pending' }).populate('userId');
        const allUsers = await User.find({});

        res.json({
            pendingDeposits,
            pendingWithdrawals,
            allUsers
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Get All Users for Admin
app.get('/api/admin/users', authenticate, async (req, res) => {
    try {
        // Fetch all users excluding sensitive information (like passwords)
        const users = await User.find({}, '-password');
        
        // Check if users were found
        if (!users.length) {
            return res.status(404).json({ message: 'No users found.' });
        }

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});





// Fetch all users with their profits
app.get('/api/admin/users/profits', async (req, res) => {
    try {
        // Assuming you have a middleware that checks if the user is an admin
        const users = await User.find({}, 'name email profits blocked'); // Exclude sensitive data
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});




// Pause or resume a specific user's profit calculation
app.post('/api/admin/users/:userId/pause-profit', async (req, res) => {
    try {
        // Assuming you have a middleware that checks if the user is an admin
        const { userId } = req.params;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Toggle the paused state for profit calculation
        user.profitPaused = !user.profitPaused; // Toggle the paused state
        await user.save();

        const status = user.profitPaused ? 'paused' : 'resumed';
        res.status(200).json({ message: `User's profit calculation has been ${status}.` });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});




// Endpoint to get all plans and calculate profits
app.get('/api/plans', authenticate, async (req, res) => {
    const { percentage } = req.query; // User-defined percentage from query parameters

    if (!percentage || isNaN(percentage)) {
        return res.status(400).json({ message: 'Percentage is required and must be a number.' });
    }

    try {
        const plans = await Plan.find({});
        const plansWithProfit = plans.map(plan => {
            const profit = (plan.baseAmount * (percentage / 100));
            return {
                name: plan.name,
                baseAmount: plan.baseAmount,
                profit: profit.toFixed(2), // Format profit to 2 decimal places
                duration: plan.duration,
                description: plan.description,
            };
        });

        res.json(plansWithProfit);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});



const seedPlans = async () => {
    const plans = [
        { name: 'Basic Plan', baseAmount: 1000, duration: '1 month', description: 'A basic investment plan.' },
        { name: 'Standard Plan', baseAmount: 5000, duration: '3 months', description: 'A standard investment plan.' },
        { name: 'Premium Plan', baseAmount: 10000, duration: '6 months', description: 'A premium investment plan.' },
    ];

    await Plan.insertMany(plans);
    console.log('Plans seeded successfully');
};

// Call this function once to seed the data (don't forget to remove or comment it out after running)
seedPlans();



// Get All Users' Profits
app.get('/api/admin/users/profits',  async (req, res) => {
    try {
        // Check if the requesting user is an admin (you may want to implement a role-checking mechanism)
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Access denied. Admins only.' });
        }

        const users = await User.find({}, 'name email profits'); // Fetch users with their profits
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Increase Specific User's Profits
app.post('/api/admin/users/profit/:userId',  async (req, res) => {
    const { amount } = req.body;
    const userId = req.params.userId;

    // Validate amount
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ message: 'Invalid amount.' });
    }

    try {
        // Find the user by userId
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Update the user's profits
        user.profits += parsedAmount;
        await user.save();

        // Emit notification to the user about the profit increase
        emitNotification(userId, `Your profits have been manually updated by an admin. Current profits: $${user.profits.toFixed(2)}`);

        res.status(200).json({ message: 'User profits updated successfully', profits: user.profits });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});



// Start server
server.listen(5000, () => {
    console.log('Server is running on port 5000');
});
