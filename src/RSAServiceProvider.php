<?php
namespace Therali\laravelRsa;

use Illuminate\Support\ServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Validator;

class RSAServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @param Request $request
     *
     * @return void
     */
    public function boot(Request $request)
    {
        $this->publishes([
            __DIR__ . '/config.php' => config_path('rsa.php'),
        ]);
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('rsa', function () {
            return $this->app->make('Therali\laravelRsa\RSALib');
        });
    }
}
