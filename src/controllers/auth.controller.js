const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Usuario = require("../models/usuario");
const UsuarioAcceso = require('../models/usuarioacceso');
const { createAccessToken } = require('../helpers/jwt.helper');
const { googleVerify } = require('../helpers/google.helper');

const login = async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        const { correo, clave } = req.body;
        const usuario = await Usuario.findOne({ correo });
        if (!usuario) {
            return res.status(400).send({
                respuesta: 'ERROR',
                mensaje: 'Usuario o contraseña incorrectos',
                datos: {
                }
            })
        }
        const isMatch = await bcrypt.compare(clave, usuario.clave);
        if (!isMatch) {
            return res.status(400).send({
                respuesta: 'ERROR',
                mensaje: 'Usuario o contraseña incorrectos',
                datos: {
                }
            })
        }
        const token = await createAccessToken({ uid: usuario._id });
        const usuarioAccesoNuevo = new UsuarioAcceso({
            usuario: usuario._id,
            token,
            host: clientIp,
            browser: userAgent
        });
        await usuarioAccesoNuevo.save();
        return res.status(200).send({
            respuesta: 'OK',
            mensaje: 'Validacion correcta',
            datos: {
                nombreUsuario: usuario.nombreUsuario,
                correo,
                token
            }
        })
    } catch (error) {
        return res.status(500).send({
            respuesta: 'EXCEPCION',
            mensaje: error.message,
            datos: {
            }
        });
    }
}
const loginGoogle = async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        const { googleToken } = req.body;

        const { nombreUsuario, fotoURL, correo } = await googleVerify(googleToken);

        const usuario = await Usuario.findOne({ correo });

        if (usuario) {
            const token = await createAccessToken({ uid: usuario._id });
            const usuarioAccesoNuevo = new UsuarioAcceso({
                usuario: usuario._id,
                token,
                host: clientIp,
                browser: userAgent
            });
            await usuarioAccesoNuevo.save();
            return res.status(200).send({
                respuesta: 'OK',
                mensaje: 'Validacion correcta',
                datos: {
                    nombreUsuario,
                    correo,
                    token
                }
            })
        }
        const userNew = new Usuario({
            nombreUsuario,
            fotoURL,
            correo,
            google: true
        });

        await userNew.save();

        const token = await createAccessToken({ uid: userNew._id });
        const usuarioAccesoNuevo = new UsuarioAcceso({
            usuario: userNew._id,
            token,
            host: clientIp,
            browser: userAgent
        });
        await usuarioAccesoNuevo.save();
        return res.status(200).send({
            respuesta: 'OK',
            mensaje: 'Validacion correcta',
            datos: {
                nombreUsuario: userNew.nombreUsuario,
                correo,
                token
            }
        })
    } catch (error) {
        return res.status(500).send({
            respuesta: 'EXCEPCION',
            mensaje: error.message,
            datos: {
            }
        })
    }
}

const registro = async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        const { correo, clave } = req.body;
        const usuario = await Usuario.findOne({ correo });
        if (usuario) {
            return res.status(400).send({
                respuesta: 'ERROR',
                mensaje: 'El correo ya se encuentra registrado',
                datos: {
                }
            })
        }
        const random = (Math.floor(Math.random() * 90000000) + 10000000).toString();
        const nombreUsuario = 'usuario' + random;
        const hashedPassword = await bcrypt.hash(clave, 10);
        const userNew = new Usuario({ nombreUsuario, correo, clave: hashedPassword });
        const userSaved = await userNew.save();
        const token = await createAccessToken({ uid: userSaved._id });
        const usuarioAccesoNuevo = new UsuarioAcceso({
            usuario: userSaved._id,
            token,
            host: clientIp,
            browser: userAgent
        });
        await usuarioAccesoNuevo.save();
        return res.status(200).send({
            respuesta: 'OK',
            mensaje: 'Usuario creado correctamente',
            datos: {
                nombreUsuario: userSaved.nombreUsuario,
                correo,
                token
            }
        })
    } catch (error) {
        return res.status(500).send({
            respuesta: 'EXCEPCION',
            mensaje: error.message,
            datos: {
            }
        });
    }
}

const verificar = async (req, res) => {
    try {
        const token = req.header('authorization');
        if (!token) return res.status(401).send({
            respuesta: 'ERROR_TOKEN_VACIO',
            mensaje: 'Token requerido',
            datos: {
            }
        });

        jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, token) => {
            if (err) return res.status(401).send({
                respuesta: 'ERROR_TOKEN_INVALIDO',
                mensaje: 'Token invalido',
                datos: {
                }
            });
            const usuario = await Usuario.findById(token.uid);
            if (!usuario) return res.status(401).send({
                respuesta: 'ERROR_TOKEN_USUARIO',
                mensaje: 'Token invalido para usuario',
                datos: {
                }
            });

            return res.status(200).send({
                respuesta: 'OK',
                mensaje: 'Token valido',
                datos: {
                    uid: usuario.id,
                    nombreUsuario: usuario.nombreUsuario,
                    correo: usuario.correo
                }
            })
        })
    } catch (error) {
        return res.status(500).send({
            respuesta: 'EXCEPCION',
            mensaje: error.message,
            datos: {
            }
        });
    }

}

module.exports = {
    login,
    loginGoogle,
    registro,
    verificar
}