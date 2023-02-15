<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

  public function __construct()
  {
    $this->middleware('auth:api', ['except' => ['login', 'register']]);
  }
  public function login(Request $request)
  {
    try {
      $validator = Validator::make($request->all(), [
        'phone' => 'required',
        'password' => 'required|string|min:6'
      ]);

      if ($validator->fails()) {
        return response()->json([
          'status' => false,
          'message' => 'validator error',
          'errors' => $validator->errors()->all()
        ], 422);
      }

      if (!$token = auth()->attempt($validator->validated())) {
        return response()->json([
          'status' => false,
          'error' => 'Unauthorized'
        ], 401);
      }

      return $this->createToken($token);
    } catch (\Exception $e) {
      return response()->json([
        'status' => false,
        'errors' => $e->getMessage()
      ], 500);
    }
  }

  public function register(Request $request)
  {
    try {
      $validator = Validator::make($request->all(), [
        'name' => 'required|string|between:2,50',
        'phone' => 'required|unique:users',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:6|confirmed|string'
      ]);

      if ($validator->fails()) {
        return response()->json([
          'status' => false,
          'message' => 'validator error',
          'errors' => $validator->errors()->all()
        ], 401);
      }

      $user = User::create([
        'name' => $request->name,
        'phone' => $request->phone,
        'email' => $request->email,
        'password' => Hash::make($request->password),
        'permission' => '2',
        'avatar' => '',
        'address' => '',
      ]);


      return $this->createToken(auth()->attempt($validator->validated()));
    } catch (\Exception $e) {
      return response()->json([
        'status' => false,
        'errors' => $e->getMessage()
      ], 500);
    }
  }

  public function logout()
  {
    auth()->logout();
    return response()->json([
      'status' => true,
      'message' => 'User successfull signed out'
    ], 200);
  }

  public function refresh()
  {
    return $this->createToken(auth()->refresh());
  }

  public function userProfile()
  {
    return response()->json(auth()->user());
  }

  public function changeAvatar(Request $request, $id)
  {
    try {
      dd($request->all());
      $user = User::findOrFail($id);
      $destination = public_path("storage\\" . $user->avatar);
      $fileName = "";
      if ($request->hasFile('new_image')) {
        if (File::exists($destination)) {
          File::delete($destination);
        }

        $fileName = $request->file('new_image')->store('posts', 'public');
      } else {
        $fileName = $user->avatar;
      }

      $user->avatar = $fileName;
      $result = $user->save();

      if ($result) {
        return response()->json([
          'status' => true,
          'message' => 'Avatar changed'
        ], 200);
      } else {
        return response()->json([
          'status' => false,
          'message' => 'change avatar failure'
        ], 500);
      }
    } catch (\Exception $e) {
      return response()->json([
        'status' => false,
        'message' => $e->getMessage()
      ], 500);
    }
  }

  protected function createToken($token)
  {
    return response()->json([
      'access_token' => $token,
      'token_type' => 'bearer',
      'expires_in' => auth('api')->factory()->getTTL() * 60,
      'user' => auth()->user()
    ], 200);
  }
}
