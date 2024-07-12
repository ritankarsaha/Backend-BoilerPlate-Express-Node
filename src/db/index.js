import mongoose from "mongoose";

import { DB_NAME } from "../constants.js";


const connectDB = async () =>{
    try{
        const connectionInstance = await mongoose.connect(`${process.env.MONGO}`)
        console.log(`\n MongoDB DATABASE CONNECTED !! DS HOST: ${connectionInstance.connection.host}`);

    }
    catch(error){
        console.log("ERROR IN THIS MONGODB connection",error)
        process.exit(1)
    }
}

export default connectDB