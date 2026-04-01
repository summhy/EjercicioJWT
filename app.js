require('dotenv').config();

const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const swaggerUi = require('swagger-ui-express')
const swaggerJsDoc = require('swagger-jsdoc')

const app = express()
app.use(express.json());

const PORT = process.env.PORT || 3000; 
const SECRET = process.env.SECRET;
const users = []

// Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Misiones con JWT',
      version: '1.0.0',
      description: 'API de ejemplo con registro, login, JWT y bcrypt'
    },
    servers: [
      {
        url: `http://localhost:${PORT}`
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ['./app.js']
};

const swaggerSpec = swaggerJsDoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))

/**
 * @swagger
 * /:
 *   get:
 *     summary: Ruta principal
 *     description: Verifica que la API esté activa
 *     tags: [General]
 *     security: []
 *     responses:
 *       200:
 *         description: API activa
 */
app.get('/', (req,res)=>{
    res.json({message: "Bienvenido a nuestro sitio"})
})

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Registro de usuario
 *     description: Crea un nuevo usuario con contraseña protegida con bcrypt
 *     security: []
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: jugador@mail.com
 *               password:
 *                 type: string
 *                 example: 1234
 *     responses:
 *       201:
 *         description: Usuario registrado correctamente
 *       400:
 *         description: Faltan datos
 *       409:
 *         description: Usuario ya existe
 */
app.post('/register', async(req, res)=> {
    try{


        const {email, password} = req.body;

        if(!email || ! password){
            return res.status(400).json('Faltan Datos');
        }
        const exists = users.find(u => u.email === email);
        if (exists){
            return res.status(409).json('Usuario ya existe');
        }

        const encripPassword = await bcrypt.hash(password, 10);

        const userNew = {
            id: users.length + 1,
            email,
            password:  encripPassword,
            rol: 'admin'
        }
        users.push(userNew);

        return res.status(201).json({message: "Usuario creado"});

    } catch (error){
        res.status(500).json(error)
    }

});


/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login de usuario
 *     description: Genera un token JWT
 *     security: []
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: jugador@mail.com
 *               password:
 *                 type: string
 *                 example: 1234
 *     responses:
 *       200:
 *         description: Login exitoso
 *       401:
 *         description: Credenciales inválidas
 *       400:
 *         description: Faltan datos
 */
app.post('/login', async (req, res)=>{
    try{
        const {email, password} = req.body;

        if(!email || ! password){
            return res.status(400).json('Faltan Datos');
        }
        const user = users.find(u => u.email === email);

        if (!user){
            return res.status(401).json({message: "Credenciales inválidas"});
        }

        const isPassword = await bcrypt.compare(password, user.password);
        if(!isPassword){
            return res.status(401).json({message: "Credenciales inválidas"});
        }


        const token = jwt.sign({
            id: user.id,
            email: user.email,
            role: user.rol
            }, SECRET, {expiresIn: '1h'})

        return res.json({message: "Login Exitoso",
                    token
        })    

    } catch (error){

        res.status(500).json(error)
    }
    
});


function authMiddleware(req, res, next){
    const authHeader = req.headers.authorization;

    if(!authHeader){
        return res.status(401).json({messager: "No existe token"})
    }

    const [schema, token] = authHeader.split(' ');

    if(schema !== 'Bearer' || !token){
        return res.status(401).json({messager: "Formato inválido"})
    }

    try{
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded
        next();

    }catch(error){
        return res.status(403).json({messager: "Error de autenticación"})
    }

}


// Middleware role
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Solo admin puede acceder' });
  }
  next();
}

function adminPlayer(req, res, next) {
  if (req.user.role !== 'Jugador') {
    return res.status(403).json({ message: 'Solo player puede acceder' });
  }
  next();
}


app.get('/misionesPlayer',authMiddleware,adminPlayer,(req,res)=>{
    return res.status(200).json({message: "Ingreso Autenticación Correcta"})
})

app.get('/misionesAdmin',authMiddleware, adminOnly, (req,res)=>{
    return res.status(200).json({message: "Ingreso Autenticación Correcta"})
})

app.get('/misiones1',(req,res)=>{
    return res.status(200).json({message: "Ingreso Autenticación Correcta"})
})

app.use((req, res)=>{
    res.status(404).json({message: 'Ruta no encontrada'})
})

app.listen(PORT, () => {
    console.log("Servicio Corriendo")
})
