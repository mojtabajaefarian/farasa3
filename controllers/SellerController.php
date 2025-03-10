<?php

namespace Controller;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

use App\Http\Controllers\Controller;

class SellerController extends BaseController
{
       public function dashboard()
       {
              $warranties = Auth::user()->warranties;
              return view('seller.dashboard', compact('warranties'));
       }
}
