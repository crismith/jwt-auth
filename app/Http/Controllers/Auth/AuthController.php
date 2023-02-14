<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{

	public function register(Request $request)
	{

		$validator = Validator::make($request->all(),[
			'name' => 'required|max:255',
			'email' => 'required|email|max:255|unique:users',
			'password' => 'required|min:6|confirmed'
		]);

		if ($validator->fails()) {
			return response()->json([
					'message' => implode(" ", $validator->errors()->all()),
					'errors' => $validator->errors()->all(),
			], 422);
		}

		$user = User::create(
			[
				'name' => $request->name,
				'email' => $request->email,
				'password' => Hash::make($request->password)
			]
		);

		$token = JWTAuth::fromUser($user);

		return response()->json([
			'user' => $user,
			'token' => $token
		]);
	}

	public function login(Request $request)
	{
		$validator = Validator::make($request->all(),[
			'email' => 'required|email',
			'password' => 'required|min:6'
		]);

		if ($validator->fails()) {
			return response()->json([
					'message' => implode(" ", $validator->errors()->all()),
					'errors' => $validator->errors()->all(),
			], 422);
		}
		
		$credentials = $request->only('email', 'password');

		try {
			if (!$token = JWTAuth::attempt($credentials)) {
				return response()->json([
					'error' => 'Token invalido'
				], 401);
			}

		} catch (JWTException $e) {
			return response()->json([
				'error' => 'Token no creado'
			], 500);
		}
		
		return response()->json(compact('token') );
	}
}
