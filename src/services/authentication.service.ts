import { User } from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { Buffer } from "buffer"; // Pour décoder Base64
import { notFound } from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key"; // Clé secrète pour signer le token

export class AuthenticationService {
  public async authenticate(
    username: string,
    password: string
  ): Promise<string> {
    // Recherche l'utilisateur dans la base de données
    const user = await User.findOne({ where: { username } });

    if (!user) {
      throw notFound("User");
    }

    // Décoder le mot de passe stocké en base de données
    const decodedPassword = Buffer.from(user.password, "base64").toString(
      "utf-8"
    );

    // Vérifie si le mot de passe est correct
    if (password === decodedPassword) {
      // Si l'utilisateur est authentifié, on génère un JWT
      let scopes :string[] = []; 

      if (user.username == "admin"){
        scopes = [  
          "user:read",
          "user:write",
          "user:delete",

          "author:read",
          "author:write",
          "author:delete",

          "book:read",
          "book:write",
          "book:delete",

          "bookCollection:read",
          "bookCollection:write",
          "bookCollection:delete",
        ] 
      }  

      if (user.username == "admin"){
        scopes = [  
          "user:read",
          "user:write",
          "user:delete",

          "author:read",
          "author:write",
          "author:delete",

          "book:read",
          "book:write",
          "book:delete",

          "bookCollection:read",
          "bookCollection:write",
          "bookCollection:delete",
        ] 
      } 

      if (user.username == "gerant"){
        scopes = [  
          "user:read",
          "user:write",

          "author:read",
          "author:write",

          "book:read",
          "book:write",

          "bookCollection:read",
          "bookCollection:write",
          "bookCollection:delete",
        ] 
      } 

      if (user.username == "utilisateur"){
        scopes = [  
          "user:read",

          "author:read",

          "book:read",
          "book:write",

          "bookCollection:read",
        ] 
      } 

      const token = jwt.sign({ 
        username: user.username,
        scopes:scopes 
      
      }, JWT_SECRET, {
        expiresIn: "1h",
      });
      return token;
    } else {
      let error = new Error("Wrong password");
      (error as any).status = 403;
      throw error;
    }
  }
}

export const authService = new AuthenticationService();
