import passport from 'passport'
import { StatusCodes } from 'http-status-codes'
import jsonwebtoken from 'jsonwebtoken'

// 這裡都在驗證，然後 next() 下一步*
export const login = (req, res, next) => {
  passport.authenticate('login', { session: false }, (error, user, info) => {
    // 'login'要對應到 passport.js 內的'login'
    if (!user || error) {
      if (info.message === 'Missing credentials') {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: '欄位錯誤'
        })
        return
      } else if (info.message === '未知錯誤') {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: '未知錯誤'
        })
        return
      } else {
        res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: info.message
        })
        return
      }
    }
    req.user = user
    next()
  })(req, res, next)
}

export const jwt = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (error, data, info) => {
    if (error || !data) {
      if (info instanceof jsonwebtoken.JsonWebTokenError) {
        // JWT 格式不對、SECRET 不對
        res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: 'JWT 無效'
        })
      } else if (info.message === '未知錯誤') {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: '未知錯誤'
        })
      } else {
        // 其他錯誤
        res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: info.message
        })
      }
    }
    req.user = data.user
    req.token = data.token
    next()
  })(req, res, next)
}
