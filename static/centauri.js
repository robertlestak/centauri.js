
(() => {
  const go = new Go();
  // change this to your own path if hosting locally
  const centauriJsVersion = 'v0.0.1';
  const centauriJsBaseURL = 'https://centauri.sh/js/' + centauriJsVersion + '/';
  WebAssembly.instantiateStreaming(fetch(centauriJsBaseURL + "main.wasm"), go.importObject).then((result) => {
      go.run(result.instance);
      // start your app here if you are dependent on the wasm module,
      // otherwise you can call the global functions as usual
  });
})()