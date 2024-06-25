const express = require('express');
const authController = require('../controllers/auth.controller');
const authValidator = require('../validators/auth.validator');

const v1AuthRouter = express.Router();

v1AuthRouter.post('/login', authValidator.login, authController.login);

v1AuthRouter.post('/login/google', authValidator.loginGoogle, authController.loginGoogle);

v1AuthRouter.post('/registro', authValidator.registro, authController.registro);

v1AuthRouter.get('/verificar', authController.verificar);

module.exports = v1AuthRouter
