import { createShader } from 'shaders/js';
import Ripples from 'shaders/core/Ripples';
import CursorRipples from 'shaders/core/CursorRipples';

export async function mount(canvas, palette, onReady, onError) {
  const instance = await createShader(canvas, {
    components: [{id:'touch',type:'CursorRipples',props:{intensity:5,decay:8,radius:.25,chromaticSplit:0},
      children:[{id:'waves',type:'Ripples',props:{colorA:palette[0],colorB:palette[1],speed:.24,frequency:10,thickness:.07,softness:.14}}]}],
  }, {components:[Ripples,CursorRipples],disableTelemetry:true,enablePerformanceTracking:false,observeElement:false,onReady,onError});
  return instance;
}
