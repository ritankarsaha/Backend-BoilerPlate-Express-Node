import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";

// access and refresh tokens
const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}
// registering the user
const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const {fullname, email, username, password } = req.body
    //console.log("email: ", email);

    if (
        [fullname, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    //console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }
    

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }
   

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email, 
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

} )
// logging the user in 
const loginUser = asyncHandler(async (req, res) =>{
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie

    const {email, username, password} = req.body
    console.log(email);

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

   const isPasswordValid = await user.isPasswordCorrect(password)

   if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials")
    }

   const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )

})
// logging out the user
const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})
// refreshing access token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
            
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200, 
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})
//changing the current password
const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = req.body
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }
    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
})


//method 1 
//get the current user
const getCurrentUser = asyncHandler(async(req, res) => {
    return res
    .status(200)
    .json(new ApiResponse(
        200,
        req.user,
        "User fetched successfully"
    ))
})

//method 2
//get a particular user from the database
const getUser = asyncHandler(async(req,res) =>{
    try {
        const user = await User.findById(req.params.id)
        const {password, ...others} = user._doc
        return res
        .status(200)
        .json(new ApiResponse(200,others,"User Details have been fetched successfully!"))
    } catch (error) {
        throw new ApiError(401, "User data couldn't be fetched successfully! ")
        
    }
})


//get all users from the database
const getAllUser = asyncHandler(async(req,res) =>{
    const query = req.query.new
    try {
        const users = query? await User.find().sort({_id:-1}).limit(5) : await User.find()
        return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                users,
                "All users have been fectched successfully from the database",
            )
        )
    } catch (error) {
        return res
        .status(401)
        .json(
            new ApiError(500, "Error while fectching all the users from the database! ")
        )
    }
})

// get user stats from the database
const getUserStats = asyncHandler(async(req,res) => {
    const date = new Date()
    const lastyear = new Date(date.setFullYear(date.getFullYear() - 1))
    try {
        const data = await User.aggregate([
             { $match: { createdAt: {$gte: lastyear } } },
          {
            $project: {
              month: { $month: "$createdAt" },
            },
          },
          {
            $group: {
              _id: "$month",
              total: { $sum: 1 },
            },
          },
        ]);
        return res
        .status(200)
        .json(
            new  ApiResponse(
                200,
                data,
                "All User data has been fetched successfully! "
            )
        )
      } catch (err) {
        throw new ApiError(401, "User stats couldn't be fetched successfully by the database! ")
      }



})

// receiing the details from the current user
const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullname, email} = req.body

    if (!fullname || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname,
                email: email
            }
        },
        {new: true}
        
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
});
// updated the user avatar here.
const updateUserAvatar = asyncHandler(async(req,res) => {
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400 , "Avatar file path is missing from this")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400 , "Error while uploading the avatar image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,{
            $set:{
             avatar: avatar.url
            }
        },{new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user,"Avatar updated successfully!" ))
})
// updated the cover image over here
const updateUserCoverImage = asyncHandler(async(req,res) => {
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400 , "Avatar file path is missing from this")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400 , "Error while uploading the avatar image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,{
            $set:{
             avatar: coverImage.url
            }
        },{new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user,"Cover Image updated successfully!" ))
})



export {registerUser , 
    loginUser ,
    logoutUser,
     refreshAccessToken ,
     changeCurrentPassword,
      getCurrentUser,
    updateAccountDetails,
updateUserAvatar,
updateUserCoverImage,
getUser,
getAllUser,
getUserStats}