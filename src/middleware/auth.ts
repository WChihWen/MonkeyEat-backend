import { auth } from "express-oauth2-jwt-bearer";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import User from "../models/user";

declare global {
    namespace Express {
        interface Request {
            userId: string;
            auth0Id: string;
        }
    }
  }

export const jwtCheck = auth({
    audience: process.env.Auth0_Audience,
    issuerBaseURL: process.env.Auth0_IssuerBaseURL,
    tokenSigningAlg: process.env.Auth0_TokenSigningAlg 
});

export const jwtParse = async (
        req: Request,
        res: Response,
        next: NextFunction
) => {
        const { authorization } = req.headers;
        
        if (!authorization || !authorization.startsWith("Bearer ")) {
            return res.sendStatus(401);
        }
        
        // Bearer lshdflshdjkhvjkshdjkvh34h5k3h54jkh
        const token = authorization.split(" ")[1];
        
        try {
            const decoded = jwt.decode(token) as jwt.JwtPayload;
            const auth0Id = decoded.sub;
        
            const user = await User.findOne({ auth0Id });
        
            if (!user) {
                return res.sendStatus(401); //unAuth
            }
        
            req.auth0Id = auth0Id as string;
            req.userId = user._id.toString();
            next(); // ==> call updateCurrentUser in the MyUserController.ts
        } catch (error) {
            return res.sendStatus(401); //unAuth
        }
};