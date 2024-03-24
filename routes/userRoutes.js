import express from "express";
import { authUser, 
    registerUser,
    logoutUser,
    getUserProfile,
    updateUserProfile
} from "../services/userController.js";
import { protect } from '../middleware/authMiddleware.js'

const router = express.Router();

router.post('/register', registerUser)
router.post('/auth', authUser)
router.post('/logout', logoutUser)
//router.route('/profile').get(protect, getUserProfile).put(protect, updateUserProfile)
 router.get('/profile', protect, getUserProfile)

export default router;